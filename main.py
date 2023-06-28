import asyncio
import datetime
import ipaddress
import json
import pathlib
from asyncio import CancelledError

from aiohttp import ClientSession, ClientTimeout, ServerDisconnectedError, ClientResponseError, ClientConnectionError, \
    TCPConnector, AsyncResolver, ClientError
from aiohttp_socks import ProxyConnector
from loguru import logger
from rich.console import Console
from rich.highlighter import NullHighlighter
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, TaskID, BarColumn, SpinnerColumn, TextColumn
from rich.table import Table

console = Console(color_system="auto", stderr=True)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address | str

online = []

logger.remove()
logger.add(
    RichHandler(
        show_level=False,
        show_path=False,
        show_time=False,
        console=console,
        highlighter=NullHighlighter()
    ),
    enqueue=True,
    colorize=True,
    diagnose=True, catch=True,
    backtrace=True,
    level='INFO'
)

MAX_ONCE_PORT = 5000  # 每个地址一次扫描端口数
DELAY_ONCE_PORT = 10  # 一次扫完扫描端口等待时间 (s)
MAX_ONCE_ADDRESS = 2  # 每次扫描地址数
DELAY_ONCE_ADDRESS = 10  # 一次扫描地址等待时间 (s)
CONNECTION_TIMEOUT = 20  # 连接超时 (s)
PORT_RANGES = [(200, 751), (10000, 65500)]  # 端口范围
REFRESH_PER_SECOND = 3  # Rich 刷新率
# MATCH = 'Stable Diffusion'  # 返回文本匹配 (这不直接弃用)

headers = {
    "Connection": 'close',
    "User-Agent": (
        'Mozilla/5.0 (X11; Linux x86_64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/114.0.0.0 '
        'Safari/537.36'
    )
}


def hcf(x, y):
    if x > y:
        smaller = y
    else:
        smaller = x

    result = -1

    for i in range(1, smaller + 1):
        if (x % i == 0) and (y % i == 0):
            result = i

    return result


@logger.catch
async def scan_port(port: int, target: str, session: ClientSession, job: Progress = None, task_id: TaskID = None):
    should_close = False

    if not session:
        should_close = True
        session = ClientSession()

    try:
        logger.trace('Connecting to http://{target}:{port}', target=target, port=port)
        async with session.get(f'http://{target}:{port}', headers=headers) as resp:
            if 200 <= resp.status < 300:
                # text = await resp.text()
                # if MATCH in text:
                logger.info(
                    '{status}: {url}',
                    status=resp.status, url=resp.url
                )
                online.append((target, port))
                return True, (target, port)
    except (TimeoutError, CancelledError):
        pass
    except (ServerDisconnectedError, ClientResponseError, ClientConnectionError):
        pass
    except ClientError:
        pass
    except Exception:
        pass
    finally:
        if job:
            job.advance(task_id)
        if should_close:
            await session.close()
    return False, (target, port)


async def scan_address(addr: IPAddress, timeout: ClientTimeout = ClientTimeout(total=CONNECTION_TIMEOUT),
                       conn: TCPConnector = None, resolver: AsyncResolver = None, job: Progress = None):
    conn = TCPConnector(loop=loop, resolver=resolver, ttl_dns_cache=200,
                        limit_per_host=MAX_ONCE_PORT) if not conn else conn
    session = ClientSession(loop=loop, connector=conn, timeout=timeout)

    task_id = None

    if job:
        total = 0
        for port_range in PORT_RANGES:
            total += port_range[1] - port_range[0]
        task_id = job.add_task(addr, total=total)

    target = addr
    if not isinstance(target, str):
        target = str(target)

    tasks = set()
    cnt = 0

    for port_range in PORT_RANGES:
        once_cnt = hcf(port_range[1] - port_range[0], MAX_ONCE_PORT)
        for port in range(port_range[0], port_range[1], once_cnt):
            if cnt >= MAX_ONCE_PORT:
                await asyncio.gather(*tuple(tasks))
                tasks = set()
                cnt = 0
                await asyncio.sleep(DELAY_ONCE_PORT)
            tasks |= {
                *[scan_port(port + i, target, session, job, task_id) for i in range(once_cnt)]
            }
            cnt += once_cnt

    await asyncio.gather(*tuple(tasks))

    await session.close()

    if job:
        job.remove_task(task_id)


async def scan():
    job_progress = Progress(
        "{task.description}",
        SpinnerColumn(),
        BarColumn(),
        TextColumn("({task.completed}/{task.total})"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    )

    overall_progress = Progress()
    overall_task = overall_progress.add_task("All", total=len(addresses))

    progress_table = Table.grid()
    progress_table.add_row(
        Panel.fit(
            overall_progress, title="All Progress", border_style="green", padding=(2, 2)
        ),
        Panel.fit(job_progress, title="[b]Scanning", border_style="red", padding=(1, 2))

    )

    file_path = pathlib.Path(f'./scan_result-{datetime.datetime.now().strftime("%Y_%m_%d_%H:%M")}.json')

    resolver = AsyncResolver(loop, nameservers=["127.0.0.53"])
    conn = TCPConnector(loop=loop, resolver=resolver, ttl_dns_cache=200, limit_per_host=20000)

    logger.info("Starting scan at {0}", datetime.datetime.now())

    with Live(progress_table, console=console, refresh_per_second=REFRESH_PER_SECOND):
        tasks = []

        cnt = 0
        for addr in addresses:
            if cnt >= MAX_ONCE_ADDRESS:
                await asyncio.gather(*tasks)
                overall_progress.advance(overall_task, cnt)
                tasks = []
                cnt = 0
                await asyncio.sleep(DELAY_ONCE_ADDRESS)
            tasks.append(scan_address(addr, conn=conn, job=job_progress))
            cnt += 1

        overall_progress.advance(overall_task, cnt)
        await asyncio.gather(*tasks)

    logger.success("Scan Complete at {0}", datetime.datetime.now())

    with file_path.open('w', encoding='u8') as fp:
        json.dump(online, fp, ensure_ascii=False)

    logger.info('Found {0} matched', len(online))
    logger.info('Saved to {0}', file_path.absolute())

    loop.run_until_complete(asyncio.sleep(0.250))


# addresses = (
#     "region-9.seetacloud.com",
#     "region-3.seetacloud.com",
#     "region-101.seetacloud.com",
#     "region-8.seetacloud.com",
#     "region-4.seetacloud.com",
#     "region-41.seetacloud.com",
#     "region-31.seetacloud.com",
# )

addresses = [f'region-{n}.seetacloud.com' for n in range(3, 105 + 1)]

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

loop.run_until_complete(scan())
loop.close()