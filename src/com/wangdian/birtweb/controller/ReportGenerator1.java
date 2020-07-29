package com.wangdian.birtweb.controller;

import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.engine.api.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Created by wd on 18-7-2.
 */
public class ReportGenerator1 {

    public static void main(String... args) {

        try {
            String engineHome = System.getProperty("user.dir") + "/ReportEngine";
            String logHome = "log/";
//            String reportFilePath = System.getProperty("user.dir") + "/appconf/" + "phishing_template1.rptdesign";
            String reportFilePath = "/home/wd/workspace/myReport/phishing_template.rptdesign";

            String reportDataPath = System.getProperty("user.dir") + "/appconf/" + "/report.txt";

            IRunAndRenderTask task = initEngine(engineHome, logHome, reportFilePath);

            StringBuilder sb = new StringBuilder();
            String str = null;
            BufferedReader reader = new BufferedReader(new FileReader(reportDataPath));
            while ((str = reader.readLine()) != null) {
                sb.append(str);
            }
            task.setParameterValue("data", sb.toString());
            task.validateParameters();
            renderProcess("docx", task);

        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    private static IRunAndRenderTask initEngine(String engineHome, String logHome, String reportPath) throws Exception {

        final EngineConfig config = new EngineConfig();
        config.setEngineHome(engineHome);
        config.setLogConfig(logHome, Level.FINE);
        Platform.startup(config);

        //If using RE API in Eclipse/RCP application this is not needed.
        IReportEngineFactory factory = (IReportEngineFactory)Platform.createFactoryObject(
            IReportEngineFactory.EXTENSION_REPORT_ENGINE_FACTORY);
        IReportEngine engine = factory.createReportEngine(config);
        engine.changeLogLevel(Level.INFO);

        IReportRunnable design;
        design = engine.openReportDesign(reportPath);

        //Create task to run and render the report,
        IRunAndRenderTask task = engine.createRunAndRenderTask(design);

        //Set parent classloader for engine
        return task;
    }

    private static void renderProcess(String cate, IRunAndRenderTask task) throws Exception {

        if ("docx".equals(cate)) {
            DocxRenderOption docxRenderOption = new DocxRenderOption();
            docxRenderOption.setOutputFormat("docx");
            task.setRenderOption(docxRenderOption);
            //run and render report
            task.run();
        } else if ("pdf".equals(cate)) {
            IRenderOption options = new RenderOption();
            PDFRenderOption pdfOptions = new PDFRenderOption(options);
            pdfOptions.setOutputFormat("pdf");
            task.setRenderOption(pdfOptions);
            //run and render report
            task.run();
            task.close();
        }
    }

}
