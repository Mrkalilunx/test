/*
 * decompall
 * 无头模式并行反编译当前程序全部函数,导出为单个 C 文件
 * 用 ChunkingParallelDecompiler 让多个反编译器同时跑,缓解大二进制的耗时
 * 用法:
 *   analyzeHeadless <项目目录> <项目名> -import <二进制> \
 *     -scriptPath <脚本目录> -postScript decompall.java <输出文件>
 */
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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

    // 单函数反编译超时秒数
    private static final int TIMEOUT_SEC = 30;
    // 每攒够这么多函数就并行反编译一批并落盘,避免结果全压在内存里
    private static final int CHUNK = 2000;

    @Override
    protected void run() throws Exception
    {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "decompiled.c";

        CachingPool<DecompInterface> pool = new CachingPool<>(new Factory(currentProgram));
        Callback cb = new Callback(pool);
        ChunkingParallelDecompiler<Result> pd =
            ParallelDecompiler.createChunkingParallelDecompiler(cb, monitor);

        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        int total = 0;
        int ok = 0;
        try {
            // 文件头记录目标元信息
            pw.println("// target: " + currentProgram.getName());
            pw.println("// format: " + currentProgram.getExecutableFormat());
            pw.println("// language: " + currentProgram.getLanguageID());
            pw.println("// imagebase: " + currentProgram.getImageBase());
            pw.println();

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            List<Function> buf = new ArrayList<>();
            // 逐个函数收集,成批交给并行反编译器
            while (it.hasNext()) {
                Function func = it.next();
                if (func.isExternal()) {
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

        // so: 如需按函数拆分成多个文件,可在 flush 里改成每函数写独立文件
        println("decompiled " + ok + "/" + total + " functions -> " + outPath);
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
            pw.println("// function " + r.name + " @ " + r.entry);
            if (r.code != null) {
                pw.println(r.code);
                ok++;
            }
            else {
                pw.println("// decompile failed");
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

        Result(String name, Address entry, String code)
        {
            this.name = name;
            this.entry = entry;
            this.code = code;
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

        Callback(CachingPool<DecompInterface> pool)
        {
            this.pool = pool;
        }

        @Override
        public Result process(Function func, TaskMonitor m) throws Exception
        {
            if (m.isCancelled()) {
                return null;
            }
            // pool.get() 会抛受检异常
            DecompInterface di = pool.get();
            try {
                DecompileResults res = di.decompileFunction(func, TIMEOUT_SEC, m);
                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction df = res.getDecompiledFunction();
                    if (df != null) {
                        return new Result(func.getName(), func.getEntryPoint(), df.getC());
                    }
                }
                return new Result(func.getName(), func.getEntryPoint(), null);
            }
            finally {
                pool.release(di);
            }
        }
    }
}
