import asyncio
import logging
import traceback
import json
from datetime import datetime
from caldera_agent import interfaces
from caldera_agent import rest_api


# Add module name to log messages
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
log.setLevel(logging.WARNING)


class Client(object):
    """
        1) run_jobs now only retrieves jobs from the CALDERA server, and updates the server that the job is pending.
            It then dispatches these jobs to a new subroutine, run_job, which is responsible for invoking the parsing,
            and execution of the job and updating the server with results. This allows run_jobs to dispatch new jobs
            while run_job is asynchronously waiting (during a blocking operation) for a jobs to finish.
        2) Configuration operations (creation of conf.yml and token creation) have been moved to agent_configurator.
        3) conf must now be loaded outside of Client and passed to the Client constructor as a dict.
        4) Construction of the caldera_server api object must now be done prior to Client construction and passed to Client's
        constructor.
        5) Client now receives an open_connections kwarg which is a dict that keeps track of currently available
        implants. This is passed on to the interface object which Client creates in __init__ and allows the interface
        to dispatch commands to specific implants.
        6) the event_loop kwarg can be used to tell Client to use a specified event loop, if event_loop is none, it will
        get the default event loop for its thread of execution.
    """

    def __init__(self, interface, server_api):
        self.server_api = server_api
        self.interface = interface
        self.notify_clients = False

    async def heartbeat(self):
        while True:
            await self.server_api.stay_alive()
            await asyncio.sleep(10)

    async def run_forever(self, long_poll=False, reconnect=5, rate=1):
        failed_pending = False
        while True:
            try:
                # fail pending jobs only once
                if not failed_pending:
                    await self.fail_pending()
                    failed_pending = True
                await self.run_jobs(long_poll)
            except Exception:
                log.error('Uncaught exception retrieved in run_forever: {}'.format(traceback.format_exc()))
            finally: 
                if not long_poll:
                    await asyncio.sleep(rate)

    async def fail_pending(self):
        # fail any pending jobs (perhaps leftover from a previous crash)
        jobs = None
        while jobs is None:
            try:
                jobs = await self.server_api.jobs(params={'status': 'pending'})
                if len(jobs):
                    log.debug("Found leftover pending jobs")
            except rest_api.RequestFailed as e:
                log.error("Request failed with status: {}".format(e.status))
            except json.JSONDecodeError:
                log.warning("json could not be decoded")

        for i, job in enumerate(jobs):
            log.debug('[JOB] {}/{} -- Failed'.format(i + 1, len(jobs)))
            # TODO: Update the REST API to include 'PATCH'
            # Tell the server that the job is pending
            job['status'] = 'failed'
            job['action']['error'] = 'found pending on restart'
            await self.server_api.jobs(job=job)

    async def run_jobs(self, long_poll):
        # GET parameters, as filters for the jobs api
        params = {'status': 'created'}
        if long_poll:
            params['wait'] = True

        jobs = None
        while jobs is None:
            try:
                jobs = await self.server_api.jobs(params=params)
            except rest_api.RequestFailed as e:
                log.error("Request failed with status: {}".format(e.status))
            except json.JSONDecodeError:
                log.warning("json could not be decoded")

        for i, job in enumerate(jobs):
            log.debug('[JOB] {}/{} -- Pending'.format(i+1, len(jobs)))
            # TODO: Update the REST API to include 'PATCH'
            # Tell the server that the job is pending
            job['status'] = 'pending'
            await self.server_api.jobs(job=job)

        for i, job in enumerate(jobs):
            log.debug('\n[JOB] {}/{} -- Running'.format(i+1, len(jobs)))
            job = (await self.run_job(job=job))
            log.debug('\n[JOB] {}/{} -- {}'.format(i+1, len(jobs), job['status']))
            # Tell the server the result of the job
            await self.server_api.jobs(job=job)
        log.debug("Completed all jobs")

    async def run_job(self, job=None):
        # run the job
        try:
            if type(job['action']) is not dict:
                print(job)
                job['status'] = 'failed'
            else:
                action, args = job['action'].popitem()
                success, result = await self.interface.run(action, args)
                if success:
                    job['status'] = 'success'
                    job['action']['result'] = result
                else:
                    job['status'] = 'failed'
                    job['action']['error'] = result
        except interfaces.NoClientError:
            job['status'] = 'failed'
            job['action']['error'] = 'no client'
        except Exception:
            log.error("Caught unhandled exception while running job:\n{}".format(traceback.format_exc()))
            job['status'] = 'failed'
            job['action']['error'] = 'agents exception'
            job['action']['exception'] = traceback.format_exc()

        return job
