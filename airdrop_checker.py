import json
import asyncio
import random
from loguru import logger
from fake_useragent import UserAgent
from curl_cffi.requests import AsyncSession, BrowserType
from eth_account.account import Account
from eth_account.messages import encode_defunct

from utils.cap_solver import Captcha
from utils.aptos import Aptos
from utils.sui import Sui


class AirdropChecker:
    def __init__(self, idx, private_key, aptos_private_key, sui_private_key, user_agent, cap_key, proxy):
        self.idx = idx
        self.evm_address = Account.from_key(private_key).address
        self.private_key = private_key
        self.aptos = Aptos(aptos_private_key)
        self.sui = Sui(private_key=sui_private_key)
        self.headers = {
            'accept': '*/*',
            'accept-language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
            'content-type': 'application/json',
            'origin': 'https://claims.movementnetwork.xyz',
            'priority': 'u=1, i',
            'referer': 'https://claims.movementnetwork.xyz/',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="124", "Google Chrome";v="124"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user_agent
        }
        self.cookies = {}
        self.sess = AsyncSession(
            proxies={
                "http": f"socks5://{proxy}",
                "https": f"socks5://{proxy}"
            },
            impersonate=BrowserType.chrome124,
            verify=False
        )
        self.cap_key = cap_key

    def _get_signature(self, message):
        encoded_msg = encode_defunct(text=message)
        signed_msg = Account().sign_message(encoded_msg, private_key=self.private_key)
        signature = signed_msg.signature.hex()

        return signature

    async def captcha(self):
        cap = Captcha(self.cap_key, 'AntiTurnstileTaskProxyLess')
        site_key = '0x4AAAAAAAzfXcBZWeFMFz8f'
        website_url = "https://claims.movementnetwork.xyz"
        result = await cap.solve_captcha(website_url, site_key)

        return result['token']

    async def verify_start(self):
        headers = self.headers.copy()

        json_data = {
            'token': await self.captcha(),
        }

        response = await self.sess.post('https://claims.movementnetwork.xyz/api/verify-start',
                                        headers=headers, json=json_data)

        if response.status_code != 200:
            raise Exception(f'account {self.idx} verify start failed ❌')

        set_cookie_headers = response.headers.get('set-cookie')
        if not set_cookie_headers:
            raise Exception(f"account ({self.idx}) login failed❌: no set-cookie")

        for cookies_part in set_cookie_headers.split(','):
            cookies = cookies_part.split(';')
            for cookie in cookies:
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    if key in ['MvMDSessionId']:
                        self.cookies[key] = value

        logger.info(f'account {self.idx} verify start success ✅')

    async def connected_wallet(self, chain):
        cookies = self.cookies.copy()

        headers = self.headers.copy()
        headers.pop('content-type')

        response = await self.sess.get('https://claims.movementnetwork.xyz/api/user/connected-wallets', cookies=cookies,
                                       headers=headers)

        if response.status_code != 200:
            raise Exception(f"account {self.idx} connected wallet failed ❌")

        res = json.loads(response.text)
        wallets = res['wallets']['data']

        connected_chains = []
        for wallet in wallets:
            connected_chains.append(wallet['chain'])

        if chain not in connected_chains:
            raise Exception(f"account {self.idx} not connected wallet {chain} ❌")

        logger.info(f'account {self.idx} connected wallet {chain} ✅')

    async def get_nonce(self):
        cookies = self.cookies.copy()

        headers = self.headers.copy()
        headers.pop('content-type')

        response = await self.sess.get('https://claims.movementnetwork.xyz/api/get-nonce', cookies=cookies,
                                       headers=headers)

        if response.status_code != 200:
            raise Exception(f"account {self.idx} get nonce failed ❌")

        res = json.loads(response.text)
        return res['nonce']

    async def get_evm_data(self):
        nonce = await self.get_nonce()
        message = f"Please sign this message to confirm ownership. nonce: {nonce}"

        json_data = {
            'address': self.evm_address,
            'message': message,
            'signature': self._get_signature(message),
            'chain': 'evm',
            'nonce': nonce,
        }

        return json_data

    async def get_aptos_data(self):
        nonce = await self.get_nonce()

        message = f'APTOS\nmessage: Please sign this message to confirm ownership. Nonce: {nonce}\nnonce: {nonce}'

        json_data = {
            'address': self.aptos.get_address(),
            'message': message,
            'signature': self.aptos.sign_message(message.encode('utf-8'))[2:],
            'publicKey': self.aptos.get_pubkey().__str__(),
            'chain': 'aptos',
            'nonce': nonce,
        }

        return json_data

    async def get_sui_data(self):
        nonce = await self.get_nonce()

        message = f'Please sign this message to confirm ownership. nonce: {nonce}'
        pubkey = self.sui.get_pubkey()[2:]
        pubkey_dict = {str(i): byte for i, byte in enumerate(pubkey)}

        json_data = {
            'address': self.sui.get_address(),
            'message': message,
            'signature': self.sui.sign_message(message),
            'publicKey': pubkey_dict,
            'chain': 'sui',
            'nonce': nonce,
        }

        return json_data

    async def verify_wallet(self, chain):
        cookies = self.cookies.copy()
        headers = self.headers.copy()

        if chain == 'evm':
            json_data = await self.get_evm_data()
        elif chain == 'aptos':
            json_data = await self.get_aptos_data()
        else:
            json_data = await self.get_sui_data()

        response = await self.sess.post('https://claims.movementnetwork.xyz/api/verify-wallet', cookies=cookies,
                                        headers=headers, json=json_data)

        if response.status_code != 200:
            raise Exception(f"account {self.idx} verify wallet failed ❌{response.text}")

        res = json.loads(response.text)
        logger.info(f"account {self.idx} verify {chain} wallet success: {res['success']}✅")

    async def eligibility(self):
        cookies = self.cookies.copy()
        headers = self.headers.copy()

        json_data = {
            'token': await self.captcha(),
        }

        response = await self.sess.post(
            'https://claims.movementnetwork.xyz/api/user/eligibility',
            cookies=cookies,
            headers=headers,
            json=json_data,
        )

        if response.status_code != 200:
            raise Exception(f"account ({self.idx}) eligibility failed ❌")

        logger.info(f"account ({self.idx}) eligibility success ✅")


async def start_airdrop_check(semaphore, idx, evm_private_key, aptos_private_key, sui_private_key, cap_key, proxy):
    async with semaphore:
        user_agent = UserAgent(browsers='chrome', os='macos', platforms='pc').random
        checker = AirdropChecker(idx, evm_private_key, aptos_private_key, sui_private_key, user_agent, cap_key, proxy)
        await asyncio.sleep(random.randint(RandomLeft, RandomRight))
        try:
            await checker.verify_start()
            #
            chains = ['evm', 'aptos', 'sui']
            for chain in chains:
                await checker.verify_wallet(chain)
                await checker.connected_wallet(chain)
                await asyncio.sleep(3)

            await checker.eligibility()
        except Exception as e:
            logger.error(f"account ({checker.idx}) complete airdrop check failed ❌：{e}")


async def main(sync_num, cap_key):
    evm_accounts, aptos_accounts, sui_accounts, proxies = load_data()

    semaphore = asyncio.Semaphore(sync_num)
    missions = []

    for idx, evm_private_key in enumerate(evm_accounts):
        missions.append(
            asyncio.create_task(
                start_airdrop_check(semaphore, idx + 1, evm_private_key, aptos_accounts[idx], sui_accounts[idx],
                                    cap_key, proxies[idx])))

    await asyncio.gather(*missions)


def load_data():
    with open('data/evm_accounts.txt', 'r', encoding='utf-8') as file:
        evm_accounts = file.read().splitlines()
        evm_accounts = [w.strip() for w in evm_accounts]
    with open('data/aptos_accounts.txt', 'r', encoding='utf-8') as file:
        aptos_accounts = file.read().splitlines()
        aptos_accounts = [w.strip() for w in aptos_accounts]
    with open('data/sui_accounts.txt', 'r', encoding='utf-8') as file:
        sui_accounts = file.read().splitlines()
        sui_accounts = [w.strip() for w in sui_accounts]
    with open('data/proxies.txt', 'r', encoding='utf-8') as file:
        proxies = file.read().splitlines()
        proxies = [p.strip() for p in proxies]

    return evm_accounts, aptos_accounts, sui_accounts, proxies


if __name__ == '__main__':
    SyncNum = 8
    CapKey = ''
    RandomLeft = 10
    RandomRight = 20
    asyncio.run(main(SyncNum, CapKey))
