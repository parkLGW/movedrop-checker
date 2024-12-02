import asyncio

import aiohttp
from loguru import logger


class Captcha:
    def __init__(self, api_key, type):
        self.CAP_SOLVER_API_KEY = api_key
        self.cap_solver_url = 'https://api.capsolver.com'
        self.type = type

    async def _create_task(self, website, site_key, page_action=None, proxy=None):
        req_data = {
            "clientKey": self.CAP_SOLVER_API_KEY,
            "task": {
                "websiteURL": website,
                "type": self.type,
                "websiteKey": site_key
            }
        }

        if page_action:
            req_data["task"]["pageAction"] = page_action

        if proxy:
            req_data["task"]["proxy"] = proxy

        async with aiohttp.ClientSession() as sess:
            async with sess.post(url=f'{self.cap_solver_url}/createTask', json=req_data) as resp:
                result = await resp.json()
                if result['errorId'] != 0:
                    raise Exception(f'创建captcha任务失败: {result["errorDescription"]}')
                return result['taskId']

    async def _wait_for_res(self, task_id):
        times = 0
        logger.info(f"正在获取captcha token……")
        while times < 120:
            try:
                req_data = {
                    "clientKey": self.CAP_SOLVER_API_KEY,
                    "taskId": task_id
                }

                async with aiohttp.ClientSession() as sess:
                    async with sess.post(url=f'{self.cap_solver_url}/getTaskResult', json=req_data) as resp:
                        result = await resp.json()
                    if result['errorId'] != 0:
                        raise Exception(f'获取captcha结果失败: {result["errorDescription"]}')
                    status = result['status']
                    if status == 'processing':
                        times += 5
                        await asyncio.sleep(5)
                        continue
                    elif status == 'ready':
                        return result['solution']
            except Exception as e:
                logger.error(f"获取token出错：{e}")
                times += 5
                await asyncio.sleep(5)

    async def solve_captcha(self, website, site_key, page_action=None, proxy=None):
        task_id = await self._create_task(website, site_key, page_action, proxy)
        return await self._wait_for_res(task_id)
