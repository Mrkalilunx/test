/*
 * decompall
 * 无头模式把当前程序的全部函数反编译并导出为单个 C 文件
 * 用法:
 *   analyzeHeadless <项目目录> <项目名> -import <二进制> \
 *     -scriptPath <脚本目录> -postScript decompall.java <输出文件>
 */
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class decompall extends GhidraScript {

    // 单函数反编译超时秒数,大二进制下调可避免整体超时
    private static final int TIMEOUT_SEC = 30;

    @Override
    protected void run() throws Exception
    {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "decompiled.c";

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));

        // 文件头记录目标元信息
        pw.println("// target: " + currentProgram.getName());
        pw.println("// format: " + currentProgram.getExecutableFormat());
        pw.println("// language: " + currentProgram.getLanguageID());
        pw.println("// imagebase: " + currentProgram.getImageBase());
        pw.println();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0;
        int ok = 0;
        // 逐个函数反编译,跳过外部符号
        while (it.hasNext() && !monitor.isCancelled()) {
            Function func = it.next();
            if (func.isExternal()) {
                continue;
            }
            total++;
            DecompileResults res = di.decompileFunction(func, TIMEOUT_SEC, monitor);
            pw.println("// function " + func.getName() + " @ " + func.getEntryPoint());
            if (res != null && res.decompileCompleted()) {
                DecompiledFunction df = res.getDecompiledFunction();
                if (df != null) {
                    pw.println(df.getC());
                    ok++;
                }
                else {
                    pw.println("// empty result");
                }
            }
            else {
                pw.println("// decompile failed");
            }
            pw.println();
        }

        pw.close();
        di.dispose();

        // so: 如需按函数拆分成多个文件,可在此处改成每函数写独立文件并以函数名命名
        println("decompiled " + ok + "/" + total + " functions -> " + outPath);
    }
}
