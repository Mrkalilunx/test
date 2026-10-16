#!/usr/bin/env python3
"""
patchsplice
把多次切片回填产出的补丁函数体合并回基准反编译文件
基准文件里失败块的形态是函数头行紧跟一行失败标记
补丁文件里同一地址的块已换成真实函数体,按地址覆盖即可
用法:
  patchsplice.py <基准文件> <输出文件>
补丁从工作目录下的 patches/patch-*.c 读取
"""

import glob
import sys

FUNC = "// function " # 函数块头行前缀
FAIL = "// decompile failed" # 失败块标记行


def addr_of(header):
    """
    取出函数头行里 " @ " 之后的地址串
    Args:
        header: 形如 // function NAME @ ADDR 的头行
    Returns:
        十六进制地址串,取不到时返回 None
    """
    i = header.rfind(" @ ")
    return header[i + 3:].strip() if i >= 0 else None


def trimmed(body):
    """
    去掉函数体尾部的空行
    Args:
        body: 函数体行列表
    Returns:
        裁掉尾随空行后的行列表
    """
    # so: 反编译产出自带尾随换行,落盘时又补过一个空行,不裁剪会越积越多
    n = len(body)
    while n > 0 and body[n - 1] == "":
        n -= 1
    return body[:n]


def blocks(path):
    """
    逐块产出反编译文件里的函数块
    Args:
        path: 待解析的反编译文件路径
    Yields:
        每块一对 (头行, 函数体行列表)
    """
    # so: 基准文件有 G 字节级别,整份读进内存太占,按行流式切块
    header = None
    body = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith(FUNC):
                if header is not None:
                    yield header, trimmed(body)
                header = line
                body = []
            elif header is not None:
                body.append(line)
    if header is not None:
        yield header, trimmed(body)


def load_patches():
    """
    读入全部补丁文件
    Returns:
        地址到函数体的映射,仍带失败标记的块不收录
    """
    # so: 补丁只含被救回的块,体量很小,多次运行的补丁可以叠加取并集
    patch = {}
    for p in sorted(glob.glob("patches/patch-*.c")):
        n = 0
        for header, body in blocks(p):
            if body and not (len(body) == 1 and body[0] == FAIL):
                patch[addr_of(header)] = body
                n += 1
        print(f"patch {p}: {n} recovered blocks")
    return patch


def main():
    """
    合并补丁并写出最终文件
    Returns:
        0 表示成功,参数不符时返回 2
    """
    if len(sys.argv) != 3:
        print("usage: patchsplice.py <base.c> <out.c>", file=sys.stderr)
        return 2
    base = sys.argv[1]
    out = sys.argv[2]
    patch = load_patches()
    print(f"total recovered in patches: {len(patch)}")

    # 统计计数,键依次为块数、失败数、补丁命中数、仍失败数
    stat = {"blocks": 0, "failed": 0, "fixed": 0, "left": 0}

    def emit(fo, header, body):
        """
        写出一个函数块,失败块能命中补丁就换掉函数体
        Args:
            fo: 输出文件对象
            header: 函数块头行
            body: 函数体行列表
        """
        stat["blocks"] += 1
        if len(body) == 1 and body[0] == FAIL:
            stat["failed"] += 1
            rep = patch.get(addr_of(header))
            if rep is None:
                stat["left"] += 1
            else:
                stat["fixed"] += 1
                body = rep
        fo.write(header + "\n")
        for line in body:
            fo.write(line + "\n")
        fo.write("\n")

    with open(base, "r", encoding="utf-8", errors="replace") as fi, \
            open(out, "w", encoding="utf-8") as fo:
        header = None
        body = []
        first = True
        for raw in fi:
            line = raw.rstrip("\n")
            if line.startswith(FUNC):
                # 首个函数块之前是文件头,原样写出
                if first:
                    for item in body:
                        fo.write(item + "\n")
                    first = False
                elif header is not None:
                    emit(fo, header, trimmed(body))
                header = line
                body = []
            else:
                body.append(line)
        if header is not None:
            emit(fo, header, trimmed(body))

    print(f"blocks: {stat['blocks']}")
    print(f"failed before: {stat['failed']}")
    print(f"fixed by patches: {stat['fixed']}")
    print(f"still failed: {stat['left']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
