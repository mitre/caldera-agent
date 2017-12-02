/*
 * Support routines from the Windows API
 *
 * This module was originally created by merging PC/_subprocess.c with
 * Modules/_multiprocessing/win32_functions.c.
 *
 * Copyright (c) 2004 by Fredrik Lundh <fredrik@pythonware.com>
 * Copyright (c) 2004 by Secret Labs AB, http://www.pythonware.com
 * Copyright (c) 2004 by Peter Astrand <astrand@lysator.liu.se>
 *
 * By obtaining, using, and/or copying this software and/or its
 * associated documentation, you agree that you have read, understood,
 * and will comply with the following terms and conditions:
 *
 * Permission to use, copy, modify, and distribute this software and
 * its associated documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice appears in
 * all copies, and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of the
 * authors not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.
 *
 * THE AUTHORS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/* Licensed to PSF under a Contributor Agreement. */
/* See http://www.python.org/2.4/license for licensing details. */

#include "Python.h"
#include "structmember.h"

#define WINDOWS_LEAN_AND_MEAN
#include "windows.h"
#include <crtdbg.h>

#if defined(MS_WIN32) && !defined(MS_WIN64)
#define HANDLE_TO_PYNUM(handle) \
    PyLong_FromUnsignedLong((unsigned long) handle)
#define PYNUM_TO_HANDLE(obj) ((HANDLE)PyLong_AsUnsignedLong(obj))
#define F_POINTER "k"
#define T_POINTER T_ULONG
#else
#define HANDLE_TO_PYNUM(handle) \
    PyLong_FromUnsignedLongLong((unsigned long long) handle)
#define PYNUM_TO_HANDLE(obj) ((HANDLE)PyLong_AsUnsignedLongLong(obj))
#define F_POINTER "K"
#define T_POINTER T_ULONGLONG
#endif

#define F_HANDLE F_POINTER
#define F_DWORD "k"
#define F_BOOL "i"
#define F_UINT "I"

#define T_HANDLE T_POINTER

#define DWORD_MAX 4294967295U

/* -------------------------------------------------------------------- */
/* windows API functions */

/* helpers for createprocess */

static unsigned long
getulong(PyObject* obj, char* name)
{
    PyObject* value;
    unsigned long ret;

    value = PyObject_GetAttrString(obj, name);
    if (! value) {
        PyErr_Clear(); /* FIXME: propagate error? */
        return 0;
    }
    ret = PyLong_AsUnsignedLong(value);
    Py_DECREF(value);
    return ret;
}

static HANDLE
gethandle(PyObject* obj, char* name)
{
    PyObject* value;
    HANDLE ret;

    value = PyObject_GetAttrString(obj, name);
    if (! value) {
        PyErr_Clear(); /* FIXME: propagate error? */
        return NULL;
    }
    if (value == Py_None)
        ret = NULL;
    else
        ret = PYNUM_TO_HANDLE(value);
    Py_DECREF(value);
    return ret;
}

static PyObject*
getenvironment(PyObject* environment)
{
    Py_ssize_t i, envsize, totalsize;
    Py_UCS4 *buffer = NULL, *p, *end;
    PyObject *keys, *values, *res;

    /* convert environment dictionary to windows environment string */
    if (! PyMapping_Check(environment)) {
        PyErr_SetString(
            PyExc_TypeError, "environment must be dictionary or None");
        return NULL;
    }

    envsize = PyMapping_Length(environment);

    keys = PyMapping_Keys(environment);
    values = PyMapping_Values(environment);
    if (!keys || !values)
        goto error;

    totalsize = 1; /* trailing null character */
    for (i = 0; i < envsize; i++) {
        PyObject* key = PyList_GET_ITEM(keys, i);
        PyObject* value = PyList_GET_ITEM(values, i);

        if (! PyUnicode_Check(key) || ! PyUnicode_Check(value)) {
            PyErr_SetString(PyExc_TypeError,
                "environment can only contain strings");
            goto error;
        }
        totalsize += PyUnicode_GET_LENGTH(key) + 1;    /* +1 for '=' */
        totalsize += PyUnicode_GET_LENGTH(value) + 1;  /* +1 for '\0' */
    }

    buffer = PyMem_Malloc(totalsize * sizeof(Py_UCS4));
    if (! buffer)
        goto error;
    p = buffer;
    end = buffer + totalsize;

    for (i = 0; i < envsize; i++) {
        PyObject* key = PyList_GET_ITEM(keys, i);
        PyObject* value = PyList_GET_ITEM(values, i);
        if (!PyUnicode_AsUCS4(key, p, end - p, 0))
            goto error;
        p += PyUnicode_GET_LENGTH(key);
        *p++ = '=';
        if (!PyUnicode_AsUCS4(value, p, end - p, 0))
            goto error;
        p += PyUnicode_GET_LENGTH(value);
        *p++ = '\0';
    }

    /* add trailing null byte */
    *p++ = '\0';
    assert(p == end);

    Py_XDECREF(keys);
    Py_XDECREF(values);

    res = PyUnicode_FromKindAndData(PyUnicode_4BYTE_KIND, buffer, p - buffer);
    PyMem_Free(buffer);
    return res;

 error:
    PyMem_Free(buffer);
    Py_XDECREF(keys);
    Py_XDECREF(values);
    return NULL;
}

PyDoc_STRVAR(CreateProcess_doc,
"CreateProcess(app_name, cmd_line, proc_attrs, thread_attrs,\n\
               inherit, flags, env_mapping, curdir,\n\
               startup_info) -> (proc_handle, thread_handle,\n\
                                 pid, tid)\n\
\n\
Create a new process and its primary thread. The return\n\
value is a tuple of the process handle, thread handle,\n\
process ID, and thread ID.\n\
\n\
proc_attrs and thread_attrs are ignored internally and can be None.");

static PyObject *
winapi_CreateProcess(PyObject* self, PyObject* args)
{
    BOOL result;
    PROCESS_INFORMATION pi;
    STARTUPINFOEXW siex;
    PyObject* environment;
    wchar_t *wenvironment;
    HANDLE parent;
    SIZE_T sizeToAlloc;
    HANDLE handles[3];
    int numHandles;

    wchar_t* application_name;
    wchar_t* command_line;
    PyObject* process_attributes; /* ignored */
    PyObject* thread_attributes; /* ignored */
    BOOL inherit_handles;
    DWORD creation_flags;
    PyObject* env_mapping;
    wchar_t* current_directory;
    PyObject* startup_info;

    if (! PyArg_ParseTuple(args, "ZZOO" F_BOOL F_DWORD "OZO:CreateProcess",
                           &application_name,
                           &command_line,
                           &process_attributes,
                           &thread_attributes,
                           &inherit_handles,
                           &creation_flags,
                           &env_mapping,
                           &current_directory,
                           &startup_info))
        return NULL;

    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);

    /* note: we only support a small subset of all SI attributes */
    siex.StartupInfo.dwFlags = getulong(startup_info, "dwFlags");
    siex.StartupInfo.wShowWindow = (WORD)getulong(startup_info, "wShowWindow");
    siex.StartupInfo.hStdInput = gethandle(startup_info, "hStdInput");
    siex.StartupInfo.hStdOutput = gethandle(startup_info, "hStdOutput");
    siex.StartupInfo.hStdError = gethandle(startup_info, "hStdError");
    if (PyErr_Occurred())
        return NULL;

    numHandles = 0;

    if (siex.StartupInfo.hStdInput)
        handles[numHandles++] = siex.StartupInfo.hStdInput;

    if (siex.StartupInfo.hStdOutput)
        handles[numHandles++] = siex.StartupInfo.hStdOutput;

    if (siex.StartupInfo.hStdError)
        handles[numHandles++] = siex.StartupInfo.hStdError;

    parent = gethandle(thread_attributes, "PARENT_PROCESS");

    if (PyErr_Occurred())
        return NULL;

    if (parent || numHandles) {
        int attributes = 0;

        if (parent)
            attributes++;
        if (numHandles)
            attributes++;

        if (InitializeProcThreadAttributeList(NULL, attributes, 0, &sizeToAlloc) || !sizeToAlloc)
        {
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)
            malloc(sizeToAlloc);

        if (siex.lpAttributeList == NULL)
            return PyErr_NoMemory();

        if (!InitializeProcThreadAttributeList(siex.lpAttributeList, attributes, 0, &sizeToAlloc))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        if (parent && !UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &parent, sizeof(parent), NULL, NULL))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        if (numHandles && !UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles, numHandles * sizeof(HANDLE), NULL, NULL))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if (env_mapping != Py_None) {
        environment = getenvironment(env_mapping);
        if (! environment) {
            DeleteProcThreadAttributeList(siex.lpAttributeList);
            free(siex.lpAttributeList);
            return NULL;
        }
        wenvironment = PyUnicode_AsUnicode(environment);
        if (wenvironment == NULL)
        {
            DeleteProcThreadAttributeList(siex.lpAttributeList);
            free(siex.lpAttributeList);
            Py_XDECREF(environment);
            return NULL;
        }
    }
    else {
        environment = NULL;
        wenvironment = NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = CreateProcessW(application_name,
                           command_line,
                           NULL,
                           NULL,
                           inherit_handles,
                           creation_flags | CREATE_UNICODE_ENVIRONMENT,
                           wenvironment,
                           current_directory,
                           &siex,
                           &pi);
    Py_END_ALLOW_THREADS

    Py_XDECREF(environment);

    DeleteProcThreadAttributeList(siex.lpAttributeList);
    free(siex.lpAttributeList);

    if (! result)
        return PyErr_SetFromWindowsErr(GetLastError());

    return Py_BuildValue("NNkk",
                         HANDLE_TO_PYNUM(pi.hProcess),
                         HANDLE_TO_PYNUM(pi.hThread),
                         pi.dwProcessId,
                         pi.dwThreadId);
}

PyDoc_STRVAR(CreateProcessAsUser_doc,
"CreateProcessAsUser(token, app_name, cmd_line, proc_attrs, thread_attrs,\n\
               inherit, flags, env_mapping, curdir,\n\
               startup_info) -> (proc_handle, thread_handle,\n\
                                 pid, tid)\n\
\n\
Create a new process and its primary thread. The return\n\
value is a tuple of the process handle, thread handle,\n\
process ID, and thread ID.\n\
\n\
proc_attrs and thread_attrs are ignored internally and can be None.");

static PyObject *
winapi_CreateProcessAsUser(PyObject* self, PyObject* args)
{
    BOOL result;
    HANDLE token;
    PROCESS_INFORMATION pi;
    STARTUPINFOEXW siex;
    PyObject* environment;
    wchar_t *wenvironment;
    HANDLE parent;
    SIZE_T sizeToAlloc;
    HANDLE handles[3];
    int numHandles;

    wchar_t* application_name;
    wchar_t* command_line;
    PyObject* process_attributes; /* ignored */
    PyObject* thread_attributes; /* ignored */
    BOOL inherit_handles;
    DWORD creation_flags;
    PyObject* env_mapping;
    wchar_t* current_directory;
    PyObject* startup_info;

    if (! PyArg_ParseTuple(args, F_HANDLE "ZZOO" F_BOOL F_DWORD "OZO:CreateProcessAsUser",
                           &token,
                           &application_name,
                           &command_line,
                           &process_attributes,
                           &thread_attributes,
                           &inherit_handles,
                           &creation_flags,
                           &env_mapping,
                           &current_directory,
                           &startup_info))
        return NULL;

    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);

    /* note: we only support a small subset of all SI attributes */
    siex.StartupInfo.dwFlags = getulong(startup_info, "dwFlags");
    siex.StartupInfo.wShowWindow = (WORD)getulong(startup_info, "wShowWindow");
    siex.StartupInfo.hStdInput = gethandle(startup_info, "hStdInput");
    siex.StartupInfo.hStdOutput = gethandle(startup_info, "hStdOutput");
    siex.StartupInfo.hStdError = gethandle(startup_info, "hStdError");
    if (PyErr_Occurred())
        return NULL;

    numHandles = 0;

    if (siex.StartupInfo.hStdInput)
        handles[numHandles++] = siex.StartupInfo.hStdInput;

    if (siex.StartupInfo.hStdOutput)
        handles[numHandles++] = siex.StartupInfo.hStdOutput;

    if (siex.StartupInfo.hStdError)
        handles[numHandles++] = siex.StartupInfo.hStdError;

    parent = gethandle(thread_attributes, "PARENT_PROCESS");

    if (PyErr_Occurred())
        return NULL;

    if (parent || numHandles) {
        int attributes = 0;

        if (parent)
            attributes++;
        if (numHandles)
            attributes++;

        if (InitializeProcThreadAttributeList(NULL, attributes, 0, &sizeToAlloc) || !sizeToAlloc)
        {
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)
            malloc(sizeToAlloc);

        if (siex.lpAttributeList == NULL)
            return PyErr_NoMemory();

        if (!InitializeProcThreadAttributeList(siex.lpAttributeList, attributes, 0, &sizeToAlloc))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        if (parent && !UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &parent, sizeof(parent), NULL, NULL))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        if (numHandles && !UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles, numHandles * sizeof(HANDLE), NULL, NULL))
        {
            free(siex.lpAttributeList);
            return PyErr_SetFromWindowsErr(GetLastError());
        }

        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if (env_mapping != Py_None) {
        environment = getenvironment(env_mapping);
        if (! environment) {
            DeleteProcThreadAttributeList(siex.lpAttributeList);
            free(siex.lpAttributeList);
            return NULL;
        }
        wenvironment = PyUnicode_AsUnicode(environment);
        if (wenvironment == NULL)
        {
            DeleteProcThreadAttributeList(siex.lpAttributeList);
            free(siex.lpAttributeList);
            Py_XDECREF(environment);
            return NULL;
        }
    }
    else {
        environment = NULL;
        wenvironment = NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = CreateProcessAsUserW(token,
                                  application_name,
                                  command_line,
                                  NULL,
                                  NULL,
                                  inherit_handles,
                                  creation_flags | CREATE_UNICODE_ENVIRONMENT,
                                  wenvironment,
                                  current_directory,
                                  &siex,
                                  &pi);
    Py_END_ALLOW_THREADS

    Py_XDECREF(environment);

    DeleteProcThreadAttributeList(siex.lpAttributeList);
    free(siex.lpAttributeList);

    if (! result)
        return PyErr_SetFromWindowsErr(GetLastError());

    return Py_BuildValue("NNkk",
                         HANDLE_TO_PYNUM(pi.hProcess),
                         HANDLE_TO_PYNUM(pi.hThread),
                         pi.dwProcessId,
                         pi.dwThreadId);
}

PyDoc_STRVAR(DuplicateCloseHandle_doc,
"DuplicateCloseHandle(source_proc_handle, source_handle,\n\
                 target_proc_handle, target_handle, access,\n\
                 inherit[, options]) -> handle\n\
\n\
Return a duplicate handle object.\n\
\n\
The duplicate handle refers to the same object as the original\n\
handle. Therefore, any changes to the object are reflected\n\
through both handles.");

static PyObject *
winapi_DuplicateCloseHandle(PyObject* self, PyObject* args)
{
    HANDLE target_handle;
    BOOL result;

    HANDLE source_process_handle;
    HANDLE source_handle;
    HANDLE target_process_handle;
    DWORD desired_access;
    BOOL inherit_handle;
    DWORD options = 0;

    if (! PyArg_ParseTuple(args,
                           F_HANDLE F_HANDLE F_HANDLE F_DWORD F_BOOL F_DWORD
                           ":DuplicateCloseHandle",
                           &source_process_handle,
                           &source_handle,
                           &target_process_handle,
                           &desired_access,
                           &inherit_handle,
                           &options))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = DuplicateHandle(
        source_process_handle,
        source_handle,
        target_process_handle,
        NULL,
        desired_access,
        inherit_handle,
        options
    );
    Py_END_ALLOW_THREADS

    if (! result)
        return PyErr_SetFromWindowsErr(GetLastError());

    return HANDLE_TO_PYNUM(target_handle);
}

static PyMethodDef foster3_functions[] = {
    {"CreateProcess", winapi_CreateProcess, METH_VARARGS,
     CreateProcess_doc},
    {"CreateProcessAsUser", winapi_CreateProcessAsUser, METH_VARARGS,
     CreateProcessAsUser_doc},
    {"DuplicateCloseHandle", winapi_DuplicateCloseHandle, METH_VARARGS,
     DuplicateCloseHandle_doc},
    {NULL, NULL}
};

static struct PyModuleDef foster3_module = {
    PyModuleDef_HEAD_INIT,
    "_foster3",
    NULL,
    -1,
    foster3_functions,
    NULL,
    NULL,
    NULL,
    NULL
};

#define WINAPI_CONSTANT(fmt, con) \
    PyDict_SetItemString(d, #con, Py_BuildValue(fmt, con))

PyMODINIT_FUNC
PyInit__foster3(void)
{
    PyObject *m;

    m = PyModule_Create(&foster3_module);
    if (m == NULL)
        return NULL;

    return m;
}