# test

helloworld 的多架构 C 构建与 GitHub Actions 云端 CI 演示

## 目录结构

| 路径 | 说明 |
|---|---|
| `main.c` | helloworld 源码,打印 `helloworld` |
| `.github/workflows/build.yml` | 多架构交叉编译并上传产物 |
| `.github/workflows/sysinfo.yml` | 采集 runner 系统信息(OS/CPU/内存/磁盘) |
| `artifacts/` | 本地下载的 CI 产物(不入库) |

## 本地构建

```bash
gcc -Wall -Wextra -O2 -o helloworld main.c
./helloworld
```

## 多架构 CI

`build.yml` 用矩阵并行编译 5 个架构,各自上传独立 artifact:

| 架构 | 交叉编译器 | 产物 |
|---|---|---|
| x86_64 | `gcc` | `helloworld-x86_64` |
| i686 | `gcc -m32` | `helloworld-i686` |
| aarch64 | `aarch64-linux-gnu-gcc` | `helloworld-aarch64` |
| armv7 | `arm-linux-gnueabihf-gcc` | `helloworld-armv7` |
| riscv64 | `riscv64-linux-gnu-gcc` | `helloworld-riscv64` |

拉取产物:

```bash
gh run download <run-id> --name helloworld-aarch64 --dir artifacts/aarch64
```

注意:产物链接 glibc,Termux 是 Android bionic,本机直接跑会报找不到动态链接器,需经 glibc loader 或 proot 运行

## Runner 规格

GitHub 托管 runner 是一次性虚拟机,任务结束即销毁,无法常驻 SSH 控制,只能用 workflow 在其存活期内执行命令并回传输出

同一标签 `ubuntu-latest`,规格随仓库可见性变化:

| 项目 | 私有仓库 | 公开仓库 |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| CPU 型号 | Intel Xeon Platinum 8370C @ 2.80GHz | AMD EPYC 7763 |
| 内存 | 8 GB | 16 GB |
| 磁盘 | 14 GB SSD | 14 GB SSD |
| 系统 | Ubuntu 24.04.5 LTS | Ubuntu 24.04.5 LTS |
| 计费 | 消耗免费额度,超出计费 | 免费无限 |

公开仓库实测(`sysinfo` workflow):

```text
Linux runnervmmprz5 6.17.0-1022-azure #22-Ubuntu SMP x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.5 LTS"
Model name:  AMD EPYC 7763 64-Core Processor
CPU(s):      4 (2 core x 2 thread)
MemTotal:    16373452 kB (~16 GB)
SwapTotal:   3145724 kB
L3 cache:    32 MiB
whoami:      runner (uid=1001, groups 含 docker)
```

## 采集 runner 信息

```bash
gh workflow run sysinfo.yml
gh run list --workflow=sysinfo.yml --limit 1
gh run view <run-id> --log
```

## 权限说明

- runner 用户为 `runner`(uid=1001),组内含 `docker`,有 sudo 免密
- 无法直接登录 runner,所有探查都靠 workflow 步骤执行
- 需要常驻可控机器时,应自建 self-hosted runner
