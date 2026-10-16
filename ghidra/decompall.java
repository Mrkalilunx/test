/*
 * decompall
 * 无头模式并行反编译当前程序全部函数,导出为单个 C 文件
 * 用 ChunkingParallelDecompiler 让多个反编译器同时跑,缓解大二进制的耗时
 * 支持分片:多个 job 各跑一片,合并时按分片号顺序拼接
 * 支持回填:对已生成文件里反编译失败的块,用更长的超时重跑并原地替换
 * 用法:
 *   analyzeHeadless <项目目录> <项目名> -process <程序> \
 *     -scriptPath <脚本目录> -postScript decompall.java <输出文件> [分片号] [分片总数] [retry]
 *   第 4 个参数为 retry 时只做回填,不重跑主流程
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class decompall extends GhidraScript {

    // 主流程单函数反编译超时秒数
    private static final int TIMEOUT_SEC = 30;
    // 回填单函数反编译超时秒数,失败的多半是超大函数被主流程超时掐掉
    private static final int RETRY_TIMEOUT_SEC = 120;
    // 每攒够这么多函数就并行反编译一批并落盘,避免结果全压在内存里
    private static final int CHUNK = 2000;
    // 失败块的标记行
    private static final String FAILED_MARK = "// decompile failed";
    // 函数块头的前缀
    private static final String FUNC_MARK = "// function ";

    @Override
    protected void run() throws Exception
    {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "decompiled.c";
        // 分片号与分片总数,只处理 index % shards == shard 的函数
        int shard = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        int shards = args.length > 2 ? Integer.parseInt(args[2]) : 1;
        boolean retryOnly = args.length > 3 && "retry".equals(args[3]);
        // 第 5 个参数可覆盖回填超时
        int retryTimeout = args.length > 4 ? Integer.parseInt(args[4]) : RETRY_TIMEOUT_SEC;

        // 只做回填时不重跑主流程
        if (retryOnly) {
            retryFailed(outPath, retryTimeout);
            return;
        }

        CachingPool<DecompInterface> pool = new CachingPool<>(new Factory(currentProgram));
        Callback cb = new Callback(pool, TIMEOUT_SEC);
        ChunkingParallelDecompiler<Result> pd =
            ParallelDecompiler.createChunkingParallelDecompiler(cb, monitor);

        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        int total = 0;
        int ok = 0;
        try {
            // 只有 0 号分片写文件头,合并时直接按分片顺序拼接即可
            if (shard == 0) {
                pw.println("// target: " + currentProgram.getName());
                pw.println("// format: " + currentProgram.getExecutableFormat());
                pw.println("// language: " + currentProgram.getLanguageID());
                pw.println("// imagebase: " + currentProgram.getImageBase());
                pw.println();
            }

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            List<Function> buf = new ArrayList<>();
            int idx = 0;
            // 逐个函数收集,属于本分片的才留下,成批交给并行反编译器
            while (it.hasNext()) {
                Function func = it.next();
                if (func.isExternal()) {
                    continue;
                }
                int mine = idx++ % shards;
                if (mine != shard) {
                    continue;
                }
                buf.add(func);
                if (buf.size() >= CHUNK) {
                    int[] r = flush(pd, buf, pw);
                    total += r[0];
                    ok += r[1];
                    buf.clear();
                }
            }
            if (!buf.isEmpty()) {
                int[] r = flush(pd, buf, pw);
                total += r[0];
                ok += r[1];
            }
        }
        finally {
            pd.dispose();
            pool.dispose();
            pw.close();
        }

        println("shard " + shard + "/" + shards + " decompiled " + ok + "/" + total
            + " functions -> " + outPath);

        // 主流程有失败块则接着回填
        if (ok < total) {
            retryFailed(outPath, retryTimeout);
        }
    }

    // 扫出文件里的失败块,用更长超时重跑,成功的结果原地替换并把仍失败的原因打印出来
    private void retryFailed(String outPath, int timeoutSec) throws Exception
    {
        List<String> addrs = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(outPath))) {
            String line;
            String held = null;
            while ((line = br.readLine()) != null) {
                if (held != null) {
                    // 上一行是函数块头,这一行是失败标记就记下地址
                    if (FAILED_MARK.equals(line)) {
                        addrs.add(addrOf(held));
                    }
                    held = null;
                }
                if (line.startsWith(FUNC_MARK)) {
                    held = line;
                }
            }
        }

        if (addrs.isEmpty()) {
            println("retry: no failed block in " + outPath);
            return;
        }
        println("retry: " + addrs.size() + " failed blocks, timeout " + timeoutSec + "s");

        // 按地址取出函数对象,并行重跑
        List<Function> funcs = new ArrayList<>();
        for (String a : addrs) {
            Address addr = addrFrom(a);
            Function f = addr == null ? null : currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f != null) {
                funcs.add(f);
            }
        }

        CachingPool<DecompInterface> pool = new CachingPool<>(new Factory(currentProgram));
        Callback cb = new Callback(pool, timeoutSec, true);
        ChunkingParallelDecompiler<Result> pd =
            ParallelDecompiler.createChunkingParallelDecompiler(cb, monitor);

        Map<String, String> bodies = new HashMap<>();
        int recovered = 0;
        try {
            for (int i = 0; i < funcs.size(); i += CHUNK) {
                List<Function> buf =
                    funcs.subList(i, Math.min(i + CHUNK, funcs.size()));
                for (Result r : pd.decompileFunctions(buf)) {
                    if (r == null) {
                        continue;
                    }
                    if (r.code != null) {
                        bodies.put(r.entry.toString(), r.code);
                        recovered++;
                    }
                }
            }
        }
        finally {
            pd.dispose();
            pool.dispose();
        }

        // 原地替换失败块
        File src = new File(outPath);
        File tmp = new File(outPath + ".tmp");
        try (BufferedReader br = new BufferedReader(new FileReader(src));
                PrintWriter out = new PrintWriter(new FileWriter(tmp))) {
            String line;
            String held = null;
            while ((line = br.readLine()) != null) {
                if (held != null) {
                    if (FAILED_MARK.equals(line)) {
                        String body = bodies.get(addrOf(held));
                        out.println(held);
                        out.println(body != null ? body : FAILED_MARK);
                        held = null;
                        continue;
                    }
                    out.println(held);
                    held = null;
                }
                if (line.startsWith(FUNC_MARK)) {
                    held = line;
                    continue;
                }
                out.println(line);
            }
            if (held != null) {
                out.println(held);
            }
        }
        // 用原子替换,避免删掉原文件后崩溃导致两个都没了
        Files.move(tmp.toPath(), src.toPath(), StandardCopyOption.REPLACE_EXISTING);

        println("retry: recovered " + recovered + " of " + addrs.size() + " failed blocks in " + outPath);
    }

    // 从 "// function NAME @ ADDR" 里取出地址串
    private static String addrOf(String funcLine)
    {
        int at = funcLine.lastIndexOf(" @ ");
        return at < 0 ? funcLine : funcLine.substring(at + 3).trim();
    }

    // 把地址串还原成 Address,一律按十六进制解析,避免十进制歧义
    private Address addrFrom(String s)
    {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        // 带地址空间前缀的交给工厂
        if (t.indexOf(':') >= 0) {
            return currentProgram.getAddressFactory().getAddress(t);
        }
        try {
            String h = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
            long off = Long.parseLong(h, 16);
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    // 并行反编译一批函数并按原顺序落盘,返回 {总数, 成功数}
    private int[] flush(ChunkingParallelDecompiler<Result> pd, List<Function> buf, PrintWriter pw)
            throws Exception
    {
        List<Result> rs = pd.decompileFunctions(buf);
        int ok = 0;
        for (Result r : rs) {
            if (r == null) {
                continue;
            }
            pw.println(FUNC_MARK + r.name + " @ " + r.entry);
            if (r.code != null) {
                pw.println(r.code);
                ok++;
            }
            else {
                pw.println(FAILED_MARK);
                println("fail: " + r.name + " @ " + r.entry + " : " + r.err);
            }
            pw.println();
        }
        pw.flush();
        return new int[] { buf.size(), ok };
    }

    // 单个函数的反编译产出
    private static class Result {
        final String name;
        final Address entry;
        final String code;
        final String err;

        Result(String name, Address entry, String code, String err)
        {
            this.name = name;
            this.entry = entry;
            this.code = code;
            this.err = err;
        }
    }

    // 为并行反编译器池按需创建 DecompInterface
    private class Factory extends CountingBasicFactory<DecompInterface> {

        private final Program program;

        Factory(Program program)
        {
            this.program = program;
        }

        @Override
        public DecompInterface doCreate(int itemNumber) throws IOException
        {
            DecompInterface di = new DecompInterface();
            di.openProgram(program);
            // 只要伪 C,不要语法树,省内存
            di.toggleSyntaxTree(false);
            return di;
        }

        @Override
        public void doDispose(DecompInterface di)
        {
            di.dispose();
        }
    }

    // 从池里借一个反编译器处理单个函数
    private class Callback implements QCallback<Function, Result> {

        private final CachingPool<DecompInterface> pool;
        private final int timeoutSec;
        // 回填时逐函数打印结果,被抢占也能看到进展与原因
        private final boolean verbose;

        Callback(CachingPool<DecompInterface> pool, int timeoutSec)
        {
            this(pool, timeoutSec, false);
        }

        Callback(CachingPool<DecompInterface> pool, int timeoutSec, boolean verbose)
        {
            this.pool = pool;
            this.timeoutSec = timeoutSec;
            this.verbose = verbose;
        }

        @Override
        public Result process(Function func, TaskMonitor m) throws Exception
        {
            if (m.isCancelled()) {
                return null;
            }
            // pool.get() 会抛受检异常
            DecompInterface di = pool.get();
            Result r;
            try {
                DecompileResults res = di.decompileFunction(func, timeoutSec, m);
                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction df = res.getDecompiledFunction();
                    if (df != null) {
                        r = new Result(func.getName(), func.getEntryPoint(), df.getC(), null);
                    }
                    else {
                        r = new Result(func.getName(), func.getEntryPoint(), null,
                            "no C output");
                    }
                }
                else {
                    String err = res == null ? "null result" : res.getErrorMessage();
                    if (err != null) {
                        err = err.replace('\n', ' ');
                    }
                    r = new Result(func.getName(), func.getEntryPoint(), null, err);
                }
            }
            finally {
                pool.release(di);
            }
            if (verbose) {
                if (r.code != null) {
                    println("retry ok: " + r.name + " @ " + r.entry);
                }
                else {
                    println("retry fail: " + r.name + " @ " + r.entry + " : " + r.err);
                }
            }
            return r;
        }
    }
}
