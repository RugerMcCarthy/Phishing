package com.wangdian.birtweb.controller;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import com.wangdian.birtweb.listener.EngineDataRequestListener;
import okhttp3.OkHttpClient;
import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.engine.api.DocxRenderOption;
import org.eclipse.birt.report.engine.api.EngineConfig;
import org.eclipse.birt.report.engine.api.IRenderOption;
import org.eclipse.birt.report.engine.api.IReportEngine;
import org.eclipse.birt.report.engine.api.IReportEngineFactory;
import org.eclipse.birt.report.engine.api.IReportRunnable;
import org.eclipse.birt.report.engine.api.IRunAndRenderTask;
import org.eclipse.birt.report.engine.api.PDFRenderOption;
import org.eclipse.birt.report.engine.api.RenderOption;

/**
 * Created by wd on 18-7-2.
 */
public class ReportGenerator {

    public static void main(String... args) {

        try {
            String engineHome = System.getProperty("user.dir") + "/ReportEngine";
            String logHome = "log/";
            String reportFilePath = System.getProperty("user.dir") + "/appconf/" + "phishing_template.rptdesign";
            String reportDataPath = System.getProperty("user.dir") + "/file_hashes.txt";

            IRunAndRenderTask task = initEngine(engineHome, logHome, reportFilePath);

            List<String> content = new ArrayList<>();
            String str;
            BufferedReader reader = new BufferedReader(new FileReader(reportDataPath));
            while ((str = reader.readLine()) != null) {
                content.add(str);
            }
            DataBuilder dataBuilder = new DataBuilder();
            dataBuilder.build(content, new EngineDataRequestListener() {
                @Override
                public void onSuccess(String data) throws Exception {
                    task.setParameterValue("data", data);
                    task.validateParameters();
                    renderProcess("docx", task);
                }

                @Override
                public void onFailure() {
                    System.out.println("Network Request Error!!!!");
                }
            });

        } catch (Exception e) {
            e.printStackTrace();
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
