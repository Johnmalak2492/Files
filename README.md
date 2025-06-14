تمام دي ال AssetsProtector.java
package com.john.protector;

import android.util.Base64;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List; // Added this import
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * فئة حماية الأصول باستخدام تشفير AES
 * تقوم بتشفير ملفات assets وحفظها بصيغة مشفرة
 */
public class AssetsProtector {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String ENCRYPTED_SUFFIX = "_encrypted.txt";
    
    private SecretKey secretKey;
    private byte[] iv;
    
    public AssetsProtector() {
        generateKey();
        generateIV();
    }
    
    /**
     * توليد مفتاح التشفير
     */
    private void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(256);
            secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("فشل في توليد مفتاح التشفير", e);
        }
    }
    
    /**
     * توليد متجه التهيئة (IV)
     */
    private void generateIV() {
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);
    }
    
    /**
     * تشفير ملفات assets
     * @param assetsDir مجلد assets
     */
    public void encryptAssets(File assetsDir, List<String> filesToEncrypt) throws Exception {
        if (!assetsDir.exists() || !assetsDir.isDirectory()) {
            throw new IllegalArgumentException("مجلد assets غير موجود");
        }

        for (String fileName : filesToEncrypt) {
            File fileToEncrypt = new File(assetsDir, fileName);
            if (fileToEncrypt.isFile()) {
                encryptFile(fileToEncrypt);
            } else {
                System.out.println("الملف غير موجود أو ليس ملفًا: " + fileName);
            }
        }
    }
    
    /**
     * تشفير ملف واحد
     * @param file الملف المراد تشفيره
     */
    private void encryptFile(File file) throws Exception {
        // قراءة محتوى الملف
        byte[] fileContent = readFileBytes(file);
        
        // تشفير المحتوى
        byte[] encryptedContent = encrypt(fileContent);
        
        // إنشاء ملف مشفر جديد
        String encryptedFileName = file.getName() + ENCRYPTED_SUFFIX;
        File encryptedFile = new File(file.getParent(), encryptedFileName);
        
        // كتابة المحتوى المشفر
        writeEncryptedFile(encryptedFile, encryptedContent);
        
        // حذف الملف الأصلي (اختياري)
        // file.delete();
    }
    
    /**
     * تشفير البيانات باستخدام AES
     * @param data البيانات المراد تشفيرها
     * @return البيانات المشفرة
     */
    private byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(data);
    }
    
    /**
     * فك تشفير البيانات
     * @param encryptedData البيانات المشفرة
     * @return البيانات الأصلية
     */
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(encryptedData);
    }
    
    /**
     * قراءة محتوى ملف كـ bytes
     * @param file الملف
     * @return محتوى الملف
     */
    private byte[] readFileBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }
    
    /**
     * كتابة الملف المشفر مع معلومات إضافية
     * @param file الملف المشفر
     * @param encryptedData البيانات المشفرة
     */
    private void writeEncryptedFile(File file, byte[] encryptedData) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            // كتابة معلومات التشفير
            String header = createEncryptionHeader();
            fos.write(header.getBytes());
            fos.write("\n---DATA---\n".getBytes());
            
            // كتابة البيانات المشفرة مُرمزة بـ Base64
            String encodedData = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            fos.write(encodedData.getBytes());
        }
    }
    
    /**
     * إنشاء رأس معلومات التشفير
     * @return رأس التشفير
     */
    private String createEncryptionHeader() {
        StringBuilder header = new StringBuilder();
        header.append("# Android Protector Encrypted File\n");
        header.append("# Algorithm: ").append(ALGORITHM).append("\n");
        header.append("# Transformation: ").append(TRANSFORMATION).append("\n");
        header.append("# Key: ").append(Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT)).append("\n");
        header.append("# IV: ").append(Base64.encodeToString(iv, Base64.DEFAULT)).append("\n");
        header.append("# Timestamp: ").append(System.currentTimeMillis()).append("\n");
        return header.toString();
    }
    
    /**
     * الحصول على مفتاح التشفير كـ String
     * @return مفتاح التشفير
     */
    public String getKeyAsString() {
        return Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
    }
    
    /**
     * الحصول على IV كـ String
     * @return متجه التهيئة
     */
    public String getIVAsString() {
        return Base64.encodeToString(iv, Base64.DEFAULT);
    }
    
    /**
     * إنشاء مفتاح من String
     * @param keyString مفتاح التشفير كـ String
     */
    public void setKeyFromString(String keyString) {
        byte[] keyBytes = Base64.decode(keyString, Base64.DEFAULT);
        secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
    }
    
    /**
     * إنشاء IV من String
     * @param ivString متجه التهيئة كـ String
     */
    public void setIVFromString(String ivString) {
        iv = Base64.decode(ivString, Base64.DEFAULT);
    }
}


ودي كلاسس ال
FileSplitter.java
package com.john.protector;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * فئة تقسيم الملفات المشفرة إلى أجزاء متعددة
 * تقوم بتقسيم الملف المشفر إلى 4 أجزاء كما هو مطلوب
 */
public class FileSplitter {
    
    private static final int DEFAULT_PARTS = 4;
    private static final String PART_SUFFIX = "_part";
    private static final String PART_EXTENSION = ".dat";
    
    /**
     * تقسيم ملفات مجلد assets المشفرة
     * @param assetsDir مجلد assets
     */
    public void splitFiles(File assetsDir) throws IOException {
        if (!assetsDir.exists() || !assetsDir.isDirectory()) {
            throw new IllegalArgumentException("مجلد assets غير موجود");
        }
        
        File[] files = assetsDir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().endsWith("_encrypted.txt")) {
                    splitFile(file, DEFAULT_PARTS);
                } else if (file.isDirectory()) {
                    splitFiles(file); // تقسيم الملفات في المجلدات الفرعية
                }
            }
        }
    }
    
    /**
     * تقسيم ملف واحد إلى أجزاء متعددة
     * @param file الملف المراد تقسيمه
     * @param parts عدد الأجزاء
     */
    public List<File> splitFile(File file, int parts) throws IOException {
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("الملف غير موجود: " + file.getName());
        }
        
        List<File> partFiles = new ArrayList<>();
        long fileSize = file.length();
        long partSize = fileSize / parts;
        long remainingBytes = fileSize % parts;
        
        try (FileInputStream fis = new FileInputStream(file)) {
            for (int i = 0; i < parts; i++) {
                // حساب حجم الجزء الحالي
                long currentPartSize = partSize;
                if (i == parts - 1) {
                    currentPartSize += remainingBytes; // إضافة الباقي للجزء الأخير
                }
                
                // إنشاء ملف الجزء
                String partFileName = getPartFileName(file, i + 1);
                File partFile = new File(file.getParent(), partFileName);
                partFiles.add(partFile);
                
                // كتابة الجزء
                writePartFile(fis, partFile, currentPartSize);
            }
        }
        
        return partFiles;
    }
    
    /**
     * كتابة جزء من الملف
     * @param input مجرى الإدخال
     * @param partFile ملف الجزء
     * @param size حجم الجزء
     */
    private void writePartFile(FileInputStream input, File partFile, long size) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(partFile)) {
            byte[] buffer = new byte[4096];
            long bytesWritten = 0;
            
            while (bytesWritten < size) {
                int bytesToRead = (int) Math.min(buffer.length, size - bytesWritten);
                int bytesRead = input.read(buffer, 0, bytesToRead);
                
                if (bytesRead == -1) {
                    break;
                }
                
                fos.write(buffer, 0, bytesRead);
                bytesWritten += bytesRead;
            }
        }
    }
    
    /**
     * إنشاء اسم ملف الجزء
     * @param originalFile الملف الأصلي
     * @param partNumber رقم الجزء
     * @return اسم ملف الجزء
     */
    private String getPartFileName(File originalFile, int partNumber) {
        String originalName = originalFile.getName();
        String baseName = originalName.substring(0, originalName.lastIndexOf('.'));
        return baseName + PART_SUFFIX + partNumber + PART_EXTENSION;
    }
    
    /**
     * دمج الأجزاء المقسمة إلى ملف واحد
     * @param partFiles قائمة ملفات الأجزاء
     * @param outputFile الملف المدموج
     */
    public void mergeFiles(List<File> partFiles, File outputFile) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            for (File partFile : partFiles) {
                if (!partFile.exists()) {
                    throw new IOException("جزء الملف غير موجود: " + partFile.getName());
                }
                
                try (FileInputStream fis = new FileInputStream(partFile)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
            }
        }
    }
    
    /**
     * البحث عن ملفات الأجزاء لملف معين
     * @param originalFile الملف الأصلي
     * @return قائمة ملفات الأجزاء
     */
    public List<File> findPartFiles(File originalFile) {
        List<File> partFiles = new ArrayList<>();
        String baseName = originalFile.getName().substring(0, originalFile.getName().lastIndexOf('.'));
        File parentDir = originalFile.getParentFile();
        
        if (parentDir != null && parentDir.exists()) {
            File[] files = parentDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    String fileName = file.getName();
                    if (fileName.startsWith(baseName + PART_SUFFIX) && fileName.endsWith(PART_EXTENSION)) {
                        partFiles.add(file);
                    }
                }
            }
        }
        
        // ترتيب الأجزاء حسب الرقم
        partFiles.sort((f1, f2) -> {
            int part1 = extractPartNumber(f1.getName());
            int part2 = extractPartNumber(f2.getName());
            return Integer.compare(part1, part2);
        });
        
        return partFiles;
    }
    
    /**
     * استخراج رقم الجزء من اسم الملف
     * @param fileName اسم الملف
     * @return رقم الجزء
     */
    private int extractPartNumber(String fileName) {
        try {
            int startIndex = fileName.indexOf(PART_SUFFIX) + PART_SUFFIX.length();
            int endIndex = fileName.lastIndexOf(PART_EXTENSION);
            String partNumberStr = fileName.substring(startIndex, endIndex);
            return Integer.parseInt(partNumberStr);
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * حذف ملفات الأجزاء
     * @param partFiles قائمة ملفات الأجزاء
     */
    public void deletePartFiles(List<File> partFiles) {
        for (File partFile : partFiles) {
            if (partFile.exists()) {
                partFile.delete();
            }
        }
    }
    
    /**
     * التحقق من وجود جميع أجزاء الملف
     * @param originalFile الملف الأصلي
     * @param expectedParts عدد الأجزاء المتوقع
     * @return true إذا كانت جميع الأجزاء موجودة
     */
    public boolean areAllPartsPresent(File originalFile, int expectedParts) {
        List<File> partFiles = findPartFiles(originalFile);
        return partFiles.size() == expectedParts;
    }
}


ودي كلاسس 
MainActivity.java
package com.john.protector;

import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.ArrayList;
import com.john.protector.SmaliAnalyzer;

public class MainActivity extends AppCompatActivity {
    
    private static final int PICK_FILE_REQUEST = 1001;
    
    // UI Components
    private Button btnSelectApp;
    private Button btnBrowseFiles;
    private Button btnStartProtection;
    private Button btnSaveResults;
    private LinearLayout layoutSelectedFile;
    private TextView tvSelectedFile;
    private ImageView ivRemoveFile;
    private CheckBox cbAssetsProtection;
    private CheckBox cbFileSplitting;
    private CheckBox cbAutoRestore;
    private CardView cardProgress;
    private CardView cardResults;
    private ProgressBar progressBar;
    private TextView tvProgressStatus;
    private TextView tvResultTitle;
    private TextView tvResultDetails;
    private ImageView ivResultIcon;
    
    // Data
    private File selectedFile;
    private ExecutorService executorService;
    private Handler mainHandler;
    
    // Protection classes
    private AssetsProtector assetsProtector;
    private FileSplitter fileSplitter;
    private MethodInjector methodInjector;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initializeComponents();
        setupEventListeners();
        
        executorService = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());
        
        // Initialize protection classes
        assetsProtector = new AssetsProtector();
        fileSplitter = new FileSplitter();
        methodInjector = new MethodInjector();
    }
    
    private void initializeComponents() {
        btnSelectApp = findViewById(R.id.btnSelectApp);
        btnBrowseFiles = findViewById(R.id.btnBrowseFiles);
        btnStartProtection = findViewById(R.id.btnStartProtection);
        btnSaveResults = findViewById(R.id.btnSaveResults);
        layoutSelectedFile = findViewById(R.id.layoutSelectedFile);
        tvSelectedFile = findViewById(R.id.tvSelectedFile);
        ivRemoveFile = findViewById(R.id.ivRemoveFile);
        cbAssetsProtection = findViewById(R.id.cbAssetsProtection);
        cbFileSplitting = findViewById(R.id.cbFileSplitting);
        cbAutoRestore = findViewById(R.id.cbAutoRestore);
        cardProgress = findViewById(R.id.cardProgress);
        cardResults = findViewById(R.id.cardResults);
        progressBar = findViewById(R.id.progressBar);
        tvProgressStatus = findViewById(R.id.tvProgressStatus);
        tvResultTitle = findViewById(R.id.tvResultTitle);
        tvResultDetails = findViewById(R.id.tvResultDetails);
        ivResultIcon = findViewById(R.id.ivResultIcon);
    }
    
    private void setupEventListeners() {
        btnSelectApp.setOnClickListener(v -> selectFile());
        btnBrowseFiles.setOnClickListener(v -> selectFile());
        btnStartProtection.setOnClickListener(v -> startProtection());
        btnSaveResults.setOnClickListener(v -> saveResults());
        ivRemoveFile.setOnClickListener(v -> removeSelectedFile());
        
        // Enable/disable protection button based on file selection
        updateProtectionButtonState();
    }
    
    private void selectFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/vnd.android.package-archive");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, "اختر ملف APK"), PICK_FILE_REQUEST);
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == PICK_FILE_REQUEST && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                handleSelectedFile(uri);
            }
        }
    }
    
    private void handleSelectedFile(Uri uri) {
        try {
            String fileName = getFileName(uri);
            selectedFile = new File(getCacheDir(), fileName);
            
            // Copy file to cache directory
            copyFileFromUri(uri, selectedFile);
            
            // Update UI
            tvSelectedFile.setText(fileName);
            layoutSelectedFile.setVisibility(View.VISIBLE);
            updateProtectionButtonState();
            
            Toast.makeText(this, "تم اختيار الملف: " + fileName, Toast.LENGTH_SHORT).show();
            
        } catch (Exception e) {
            Toast.makeText(this, "خطأ في اختيار الملف: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
    
    private String getFileName(Uri uri) {
        String path = uri.getPath();
        if (path != null) {
            return path.substring(path.lastIndexOf('/') + 1);
        }
        return "selected_file.apk";
    }
    
    private void copyFileFromUri(Uri uri, File destFile) throws IOException {
        try (FileInputStream input = (FileInputStream) getContentResolver().openInputStream(uri);
             FileOutputStream output = new FileOutputStream(destFile)) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }
    }
    
    private void removeSelectedFile() {
        selectedFile = null;
        layoutSelectedFile.setVisibility(View.GONE);
        updateProtectionButtonState();
        Toast.makeText(this, "تم إلغاء اختيار الملف", Toast.LENGTH_SHORT).show();
    }
    
    private void updateProtectionButtonState() {
        btnStartProtection.setEnabled(selectedFile != null);
    }
    
    private void startProtection() {
        if (selectedFile == null) {
            Toast.makeText(this, "يرجى اختيار ملف أولاً", Toast.LENGTH_SHORT).show();
            return;
        }
        
        // Show progress card
        cardProgress.setVisibility(View.VISIBLE);
        cardResults.setVisibility(View.GONE);
        progressBar.setProgress(0);
        tvProgressStatus.setText("بدء عملية الحماية...");
        
        // Disable UI during processing
        setUIEnabled(false);
        
        // Start protection process in background
        executorService.execute(() -> performProtection());
    }
    
    private void performProtection() {
        try {
            updateProgress(10, "استخراج ملفات APK...");
            Thread.sleep(1000);
                        // Extract APK using apktool
            File extractedDir = new File(getCacheDir(), "extracted");
            extractedDir.mkdirs();
            String apktoolPath = "apktool"; // Assuming apktool is in PATH
            ProcessBuilder processBuilder = new ProcessBuilder(apktoolPath, "d", selectedFile.getAbsolutePath(), "-o", extractedDir.getAbsolutePath());
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Log apktool output if needed
                System.out.println(line);
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Apktool decompilation failed with exit code " + exitCode);
            }

            updateProgress(25, "تحليل ملفات Smali لتحديد Assets المستدعاة...");
            List<String> filesToEncrypt = SmaliAnalyzer.findAccessedAssets(extractedDir);
            if (filesToEncrypt.isEmpty()) {
                Toast.makeText(this, "لم يتم العثور على ملفات Assets مستدعاة في الكود.", Toast.LENGTH_LONG).show();
                mainHandler.post(() -> showErrorResult("لم يتم العثور على ملفات Assets مستدعاة."));
                return;
            }

            updateProgress(40, "تشفير ملفات Assets المحددة...");
            Thread.sleep(1500);
            
            // Encrypt assets
            assetsProtector.encryptAssets(new File(extractedDir, "assets"), filesToEncrypt);          
            if (cbFileSplitting.isChecked()) {
                updateProgress(60, "تقسيم الملفات المشفرة...");
                Thread.sleep(1500);
                
                // Split encrypted files
                fileSplitter.splitFiles(new File(extractedDir, "assets"));
            }
            
            if (cbAutoRestore.isChecked()) {
                updateProgress(80, "حقن كود الاسترجاع...");
                Thread.sleep(1500);
                
                // Inject restoration code
                methodInjector.injectRestorationCode(extractedDir);
            }
            
            updateProgress(95, "إعادة بناء APK...");
            Thread.sleep(1000);
            
            // Rebuild APK
            File protectedApk = new File(getCacheDir(), "protected_app.apk");
            ProcessBuilder rebuildProcessBuilder = new ProcessBuilder(apktoolPath, "b", extractedDir.getAbsolutePath(), "-o", protectedApk.getAbsolutePath());
            rebuildProcessBuilder.redirectErrorStream(true);
            Process rebuildProcess = rebuildProcessBuilder.start();

            BufferedReader rebuildReader = new BufferedReader(new InputStreamReader(rebuildProcess.getInputStream()));
            String rebuildLine;
            while ((rebuildLine = rebuildReader.readLine()) != null) {
                System.out.println(rebuildLine);
            }

            int rebuildExitCode = rebuildProcess.waitFor();
            if (rebuildExitCode != 0) {
                throw new IOException("Apktool rebuilding failed with exit code " + rebuildExitCode);
            }
            
            updateProgress(100, "تمت الحماية بنجاح!");
            
            // Show success result
            mainHandler.post(() -> showSuccessResult());
            
        } catch (Exception e) {
            mainHandler.post(() -> showErrorResult(e.getMessage()));
        }
    }
    
    private void updateProgress(int progress, String status) {
        mainHandler.post(() -> {
            progressBar.setProgress(progress);
            tvProgressStatus.setText(status);
        });
    }
    
    private void showSuccessResult() {
        cardProgress.setVisibility(View.GONE);
        cardResults.setVisibility(View.VISIBLE);
        
        ivResultIcon.setImageResource(R.drawable.ic_success);
        tvResultTitle.setText("تمت الحماية بنجاح!");
        tvResultTitle.setTextColor(getResources().getColor(android.R.color.holo_green_dark));
        
        String details = "تم تطبيق الحماية التالية:\n";
        if (cbAssetsProtection.isChecked()) details += "• تشفير Assets\n";
        if (cbFileSplitting.isChecked()) details += "• تقسيم الملفات\n";
        if (cbAutoRestore.isChecked()) details += "• الاسترجاع التلقائي\n";
        
        tvResultDetails.setText(details);
        
        setUIEnabled(true);
    }
    
    private void showErrorResult(String error) {
        cardProgress.setVisibility(View.GONE);
        cardResults.setVisibility(View.VISIBLE);
        
        ivResultIcon.setImageResource(android.R.drawable.ic_dialog_alert);
        tvResultTitle.setText("فشلت عملية الحماية");
        tvResultTitle.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
        tvResultDetails.setText("خطأ: " + error);
        
        setUIEnabled(true);
    }
    
    private void saveResults() {
        // TODO: Implement save results functionality
        Toast.makeText(this, "سيتم تنفيذ حفظ النتائج قريباً", Toast.LENGTH_SHORT).show();
    }
    
    private void setUIEnabled(boolean enabled) {
        btnSelectApp.setEnabled(enabled);
        btnBrowseFiles.setEnabled(enabled);
        btnStartProtection.setEnabled(enabled && selectedFile != null);
        cbAssetsProtection.setEnabled(enabled);
        cbFileSplitting.setEnabled(enabled);
        cbAutoRestore.setEnabled(enabled);
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executorService != null) {
            executorService.shutdown();
        }
    }
}


ودي كلاسس
MethodInjector.java
package com.john.protector;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/**
 * فئة حقن كود الاسترجاع في التطبيق المحمي
 * تقوم بإضافة الكود اللازم لاسترجاع الملفات المشفرة والمقسمة
 */
public class MethodInjector {
    
    private static final String RESTORATION_CLASS_NAME = "AssetsRestorer";
    private static final String RESTORATION_METHOD_NAME = "restoreAssets";
    
    /**
     * حقن كود الاسترجاع في التطبيق
     * @param extractedDir مجلد التطبيق المستخرج
     */
    public void injectRestorationCode(File extractedDir) throws IOException {
        // إنشاء فئة الاسترجاع
        createRestorationClass(extractedDir);
        
        // إضافة استدعاء الاسترجاع في MainActivity
        injectRestorationCall(extractedDir);
        
        // إضافة معلومات التشفير
        createEncryptionInfo(extractedDir);
    }
    
    /**
     * إنشاء فئة الاسترجاع
     * @param extractedDir مجلد التطبيق المستخرج
     */
    private void createRestorationClass(File extractedDir) throws IOException {
        File javaDir = new File(extractedDir, "src/main/java/com/john/protector");
        javaDir.mkdirs();
        
        File restorationFile = new File(javaDir, RESTORATION_CLASS_NAME + ".java");
        
        try (FileWriter writer = new FileWriter(restorationFile)) {
            writer.write(generateRestorationClassCode());
        }
    }
    
    /**
     * توليد كود فئة الاسترجاع
     * @return كود فئة الاسترجاع
     */
    private String generateRestorationClassCode() {
        StringBuilder code = new StringBuilder();
        
        code.append("package com.john.protector;\n\n");
        code.append("import android.content.Context;\n");
        code.append("import android.util.Base64;\n");
        code.append("import java.io.*;\n");
        code.append("import java.util.*;\n");
        code.append("import javax.crypto.Cipher;\n");
        code.append("import javax.crypto.spec.IvParameterSpec;\n");
        code.append("import javax.crypto.spec.SecretKeySpec;\n\n");
        
        code.append("/**\n");
        code.append(" * فئة استرجاع الأصول المشفرة والمقسمة\n");
        code.append(" * تم إنشاؤها تلقائياً بواسطة Android Protector\n");
        code.append(" */\n");
        code.append("public class ").append(RESTORATION_CLASS_NAME).append(" {\n\n");
        
        // إضافة الثوابت
        code.append("    private static final String ALGORITHM = \"AES\";\n");
        code.append("    private static final String TRANSFORMATION = \"AES/CBC/PKCS5Padding\";\n");
        code.append("    private static final String PART_SUFFIX = \"_part\";\n");
        code.append("    private static final String PART_EXTENSION = \".dat\";\n\n");
        
        // إضافة متغيرات التشفير
        code.append("    private static final String ENCRYPTION_KEY = \"{{ENCRYPTION_KEY}}\";\n");
        code.append("    private static final String ENCRYPTION_IV = \"{{ENCRYPTION_IV}}\";\n\n");
        
        // إضافة الطريقة الرئيسية للاسترجاع
        code.append("    /**\n");
        code.append("     * استرجاع جميع الأصول المشفرة\n");
        code.append("     * @param context سياق التطبيق\n");
        code.append("     */\n");
        code.append("    public static void ").append(RESTORATION_METHOD_NAME).append("(Context context) {\n");
        code.append("        try {\n");
        code.append("            File assetsDir = new File(context.getFilesDir(), \"restored_assets\");\n");
        code.append("            assetsDir.mkdirs();\n\n");
        code.append("            // البحث عن الملفات المقسمة\n");
        code.append("            List<String> encryptedFiles = findEncryptedFiles(context);\n\n");
        code.append("            for (String fileName : encryptedFiles) {\n");
        code.append("                restoreFile(context, fileName, assetsDir);\n");
        code.append("            }\n\n");
        code.append("        } catch (Exception e) {\n");
        code.append("            e.printStackTrace();\n");
        code.append("        }\n");
        code.append("    }\n\n");
        
        // إضافة طريقة البحث عن الملفات المشفرة
        code.append("    /**\n");
        code.append("     * البحث عن الملفات المشفرة في assets\n");
        code.append("     * @param context سياق التطبيق\n");
        code.append("     * @return قائمة أسماء الملفات المشفرة\n");
        code.append("     */\n");
        code.append("    private static List<String> findEncryptedFiles(Context context) {\n");
        code.append("        List<String> encryptedFiles = new ArrayList<>();\n");
        code.append("        try {\n");
        code.append("            String[] assetFiles = context.getAssets().list(\"\");\n");
        code.append("            if (assetFiles != null) {\n");
        code.append("                for (String fileName : assetFiles) {\n");
        code.append("                    if (fileName.contains(PART_SUFFIX) && fileName.endsWith(PART_EXTENSION)) {\n");
        code.append("                        String baseName = extractBaseName(fileName);\n");
        code.append("                        if (!encryptedFiles.contains(baseName)) {\n");
        code.append("                            encryptedFiles.add(baseName);\n");
        code.append("                        }\n");
        code.append("                    }\n");
        code.append("                }\n");
        code.append("            }\n");
        code.append("        } catch (IOException e) {\n");
        code.append("            e.printStackTrace();\n");
        code.append("        }\n");
        code.append("        return encryptedFiles;\n");
        code.append("    }\n\n");
        
        // إضافة طريقة استرجاع ملف واحد
        code.append("    /**\n");
        code.append("     * استرجاع ملف واحد من الأجزاء المقسمة\n");
        code.append("     * @param context سياق التطبيق\n");
        code.append("     * @param baseName اسم الملف الأساسي\n");
        code.append("     * @param outputDir مجلد الإخراج\n");
        code.append("     */\n");
        code.append("    private static void restoreFile(Context context, String baseName, File outputDir) {\n");
        code.append("        try {\n");
        code.append("            // دمج الأجزاء\n");
        code.append("            byte[] mergedData = mergeFileParts(context, baseName);\n\n");
        code.append("            // فك التشفير\n");
        code.append("            byte[] decryptedData = decrypt(mergedData);\n\n");
        code.append("            // حفظ الملف المسترجع\n");
        code.append("            File restoredFile = new File(outputDir, baseName);\n");
        code.append("            try (FileOutputStream fos = new FileOutputStream(restoredFile)) {\n");
        code.append("                fos.write(decryptedData);\n");
        code.append("            }\n\n");
        code.append("        } catch (Exception e) {\n");
        code.append("            e.printStackTrace();\n");
        code.append("        }\n");
        code.append("    }\n\n");
        
        // إضافة طريقة دمج الأجزاء
        code.append("    /**\n");
        code.append("     * دمج أجزاء الملف المقسم\n");
        code.append("     * @param context سياق التطبيق\n");
        code.append("     * @param baseName اسم الملف الأساسي\n");
        code.append("     * @return البيانات المدموجة\n");
        code.append("     */\n");
        code.append("    private static byte[] mergeFileParts(Context context, String baseName) throws IOException {\n");
        code.append("        ByteArrayOutputStream baos = new ByteArrayOutputStream();\n");
        code.append("        int partNumber = 1;\n\n");
        code.append("        while (true) {\n");
        code.append("            String partFileName = baseName + PART_SUFFIX + partNumber + PART_EXTENSION;\n");
        code.append("            try (InputStream is = context.getAssets().open(partFileName)) {\n");
        code.append("                byte[] buffer = new byte[4096];\n");
        code.append("                int bytesRead;\n");
        code.append("                while ((bytesRead = is.read(buffer)) != -1) {\n");
        code.append("                    baos.write(buffer, 0, bytesRead);\n");
        code.append("                }\n");
        code.append("                partNumber++;\n");
        code.append("            } catch (IOException e) {\n");
        code.append("                break; // لا توجد أجزاء أخرى\n");
        code.append("            }\n");
        code.append("        }\n\n");
        code.append("        return baos.toByteArray();\n");
        code.append("    }\n\n");
        
        // إضافة طريقة فك التشفير
        code.append("    /**\n");
        code.append("     * فك تشفير البيانات\n");
        code.append("     * @param encryptedData البيانات المشفرة\n");
        code.append("     * @return البيانات الأصلية\n");
        code.append("     */\n");
        code.append("    private static byte[] decrypt(byte[] encryptedData) throws Exception {\n");
        code.append("        // تحويل المفتاح و IV من Base64\n");
        code.append("        byte[] keyBytes = Base64.decode(ENCRYPTION_KEY, Base64.DEFAULT);\n");
        code.append("        byte[] ivBytes = Base64.decode(ENCRYPTION_IV, Base64.DEFAULT);\n\n");
        code.append("        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);\n");
        code.append("        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);\n\n");
        code.append("        Cipher cipher = Cipher.getInstance(TRANSFORMATION);\n");
        code.append("        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);\n\n");
        code.append("        return cipher.doFinal(encryptedData);\n");
        code.append("    }\n\n");
        
        // إضافة طريقة استخراج الاسم الأساسي
        code.append("    /**\n");
        code.append("     * استخراج الاسم الأساسي من اسم جزء الملف\n");
        code.append("     * @param partFileName اسم جزء الملف\n");
        code.append("     * @return الاسم الأساسي\n");
        code.append("     */\n");
        code.append("    private static String extractBaseName(String partFileName) {\n");
        code.append("        int partIndex = partFileName.indexOf(PART_SUFFIX);\n");
        code.append("        if (partIndex != -1) {\n");
        code.append("            return partFileName.substring(0, partIndex);\n");
        code.append("        }\n");
        code.append("        return partFileName;\n");
        code.append("    }\n");
        
        code.append("}\n");
        
        return code.toString();
    }
    
    /**
     * حقن استدعاء الاسترجاع في MainActivity
     * @param extractedDir مجلد التطبيق المستخرج
     */
    private void injectRestorationCall(File extractedDir) throws IOException {
        // هذه الطريقة ستحتاج إلى تحليل ملف MainActivity الموجود
        // وإضافة استدعاء AssetsRestorer.restoreAssets(this) في onCreate
        
        // للبساطة، سنقوم بإنشاء ملف تعليمات للمطور
        File instructionsFile = new File(extractedDir, "RESTORATION_INSTRUCTIONS.txt");
        
        try (FileWriter writer = new FileWriter(instructionsFile)) {
            writer.write("تعليمات حقن كود الاسترجاع:\n\n");
            writer.write("1. أضف الاستيراد التالي في بداية MainActivity:\n");
            writer.write("   import com.john.protector.AssetsRestorer;\n\n");
            writer.write("2. أضف السطر التالي في طريقة onCreate بعد setContentView:\n");
            writer.write("   AssetsRestorer.restoreAssets(this);\n\n");
            writer.write("3. تأكد من وجود الأذونات اللازمة في AndroidManifest.xml:\n");
            writer.write("   <uses-permission android:name=\"android.permission.WRITE_EXTERNAL_STORAGE\" />\n");
            writer.write("   <uses-permission android:name=\"android.permission.READ_EXTERNAL_STORAGE\" />\n\n");
            writer.write("4. تأكد من نسخ ملف AssetsRestorer.java إلى مجلد src/main/java/com/john/protector/\n");
        }
    }
    
    /**
     * إنشاء ملف معلومات التشفير
     * @param extractedDir مجلد التطبيق المستخرج
     */
    private void createEncryptionInfo(File extractedDir) throws IOException {
        File encryptionInfoFile = new File(extractedDir, "encryption_info.txt");
        
        try (FileWriter writer = new FileWriter(encryptionInfoFile)) {
            writer.write("معلومات التشفير:\n\n");
            writer.write("Algorithm: AES\n");
            writer.write("Transformation: AES/CBC/PKCS5Padding\n");
            writer.write("Key Size: 256 bits\n");
            writer.write("IV Size: 128 bits\n\n");
            writer.write("ملاحظة: يجب استبدال {{ENCRYPTION_KEY}} و {{ENCRYPTION_IV}} \n");
            writer.write("في ملف AssetsRestorer.java بالقيم الفعلية للمفتاح ومتجه التهيئة.\n");
        }
    }
    
    /**
     * تحديث معلومات التشفير في فئة الاسترجاع
     * @param extractedDir مجلد التطبيق المستخرج
     * @param encryptionKey مفتاح التشفير
     * @param encryptionIV متجه التهيئة
     */
    public void updateEncryptionInfo(File extractedDir, String encryptionKey, String encryptionIV) throws IOException {
        File restorationFile = new File(extractedDir, "src/main/java/com/john/protector/" + RESTORATION_CLASS_NAME + ".java");
        
        if (restorationFile.exists()) {
            // قراءة محتوى الملف
            StringBuilder content = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(restorationFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }
            
            // استبدال القيم
            String updatedContent = content.toString()
                    .replace("{{ENCRYPTION_KEY}}", encryptionKey)
                    .replace("{{ENCRYPTION_IV}}", encryptionIV);
            
            // كتابة المحتوى المحدث
            try (FileWriter writer = new FileWriter(restorationFile)) {
                writer.write(updatedContent);
            }
        }
    }
}


ودي كلاسس ال
SmaliAnalyzer.java
package com.john.protector;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SmaliAnalyzer {

    public static List<String> findAccessedAssets(File decompiledApkDir) {
        Set<String> accessedAssets = new HashSet<>();
        File smaliDir = new File(decompiledApkDir, "smali");

        if (!smaliDir.exists() || !smaliDir.isDirectory()) {
            System.out.println("Smali directory not found: " + smaliDir.getAbsolutePath());
            return new ArrayList<>(accessedAssets);
        }

        traverseSmaliFiles(smaliDir, accessedAssets);

        return new ArrayList<>(accessedAssets);
    }

    private static void traverseSmaliFiles(File dir, Set<String> accessedAssets) {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                traverseSmaliFiles(file, accessedAssets);
            } else if (file.isFile() && file.getName().endsWith(".smali")) {
                analyzeSmaliFile(file, accessedAssets);
            }
        }
    }

    private static void analyzeSmaliFile(File smaliFile, Set<String> accessedAssets) {
        try (BufferedReader reader = new BufferedReader(new FileReader(smaliFile))) {
            String line;
            String currentStringLiteral = null;
            while ((line = reader.readLine()) != null) {
                // Look for string literals that might be asset names
                 if (line.trim().startsWith("const-string")) {
                    // Extract the string literal
                    int firstQuote = line.indexOf('"');
                    int lastQuote = line.lastIndexOf('"');
                    if (firstQuote != -1 && lastQuote != -1 && firstQuote != lastQuote) {
                        currentStringLiteral = line.substring(firstQuote + 1, lastQuote);
                    }
                } else if (currentStringLiteral != null && line.contains("Landroid/content/res/AssetManager;->open(") || line.contains("Landroid/content/res/AssetManager;->openFd(")) {
                    // If a string literal was just defined and now an AssetManager.open call is made
                    // This is a heuristic, might need refinement for complex cases
                    accessedAssets.add(currentStringLiteral);
                    currentStringLiteral = null; // Reset after use
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


+ ملفات ال res اهي 

folder ال drawable 
ده اول ملف
button_outline.xml
<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android">
    <stroke android:width="2dp" android:color="#2196F3" />
    <solid android:color="#FFFFFF" />
    <corners android:radius="8dp" />
</shape>


و ده ثاني ملف button_primary.xml

<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android">
    <solid android:color="#2196F3" />
    <corners android:radius="8dp" />
</shape>

وده ثالث ملف button_success.xml

<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android">
    <solid android:color="#4CAF50" />
    <corners android:radius="8dp" />
</shape>

وده رابع ملف file_background.xml

<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android">
    <solid android:color="#F5F5F5" />
    <stroke android:width="1dp" android:color="#E0E0E0" />
    <corners android:radius="8dp" />
</shape>

وده خامس ملف header_background.xml
<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android">
    <solid android:color="#F5F5F5" />
    <stroke android:width="1dp" android:color="#E0E0E0" />
    <corners android:radius="8dp" />
</shape>

وده سادس ملف ic_assets.xml

<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#2196F3"
        android:pathData="M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6M13,3.5L18.5,9H13V3.5Z" />
</vector>


وده سابع ملف ic_close.xml
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#999999"
        android:pathData="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z" />
</vector>

وده ثامن ملف ic_file.xml

<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#666666"
        android:pathData="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z" />
</vector>


وده تاسع ملف ic_launcher_background.xml

<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#3DDC84"
        android:pathData="M0,0h108v108h-108z" />
    <path
        android:fillColor="#00000000"
        android:pathData="M9,0L9,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,0L19,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M29,0L29,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M39,0L39,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M49,0L49,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M59,0L59,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M69,0L69,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M79,0L79,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M89,0L89,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M99,0L99,108"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,9L108,9"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,19L108,19"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,29L108,29"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,39L108,39"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,49L108,49"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,59L108,59"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,69L108,69"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,79L108,79"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,89L108,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M0,99L108,99"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,29L89,29"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,39L89,39"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,49L89,49"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,59L89,59"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,69L89,69"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M19,79L89,79"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M29,19L29,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M39,19L39,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M49,19L49,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M59,19L59,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M69,19L69,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
    <path
        android:fillColor="#00000000"
        android:pathData="M79,19L79,89"
        android:strokeWidth="0.8"
        android:strokeColor="#33FFFFFF" />
</vector>

وده عاشر ملف ic_shield.xml

<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FFFFFF"
        android:pathData="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10V11.5C15.4,11.5 16,12.4 16,13V16C16,17.4 15.4,18 14.8,18H9.2C8.6,18 8,17.4 8,16V13C8,12.4 8.6,11.5 9.2,11.5V10C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10V11.5H13.5V10C13.5,8.7 12.8,8.2 12,8.2Z" />
</vector>


وده الملف ال 11 ic_success.xml

<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#4CAF50"
        android:pathData="M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z" />
</vector>

جوا فولد drawable-v24 
في ملف واحد اسمه ic_launcher_foreground.xml

وهو ده 
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:aapt="http://schemas.android.com/aapt"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path android:pathData="M31,63.928c0,0 6.4,-11 12.1,-13.1c7.2,-2.6 26,-1.4 26,-1.4l38.1,38.1L107,108.928l-32,-1L31,63.928z">
        <aapt:attr name="android:fillColor">
            <gradient
                android:endX="85.84757"
                android:endY="92.4963"
                android:startX="42.9492"
                android:startY="49.59793"
                android:type="linear">
                <item
                    android:color="#44000000"
                    android:offset="0.0" />
                <item
                    android:color="#00000000"
                    android:offset="1.0" />
            </gradient>
        </aapt:attr>
    </path>
    <path
        android:fillColor="#FFFFFF"
        android:fillType="nonZero"
        android:pathData="M65.3,45.828l3.8,-6.6c0.2,-0.4 0.1,-0.9 -0.3,-1.1c-0.4,-0.2 -0.9,-0.1 -1.1,0.3l-3.9,6.7c-6.3,-2.8 -13.4,-2.8 -19.7,0l-3.9,-6.7c-0.2,-0.4 -0.7,-0.5 -1.1,-0.3C38.8,38.328 38.7,38.828 38.9,39.228l3.8,6.6C36.2,49.428 31.7,56.028 31,63.928h46C76.3,56.028 71.8,49.428 65.3,45.828zM43.4,57.328c-0.8,0 -1.5,-0.5 -1.8,-1.2c-0.3,-0.7 -0.1,-1.5 0.4,-2.1c0.5,-0.5 1.4,-0.7 2.1,-0.4c0.7,0.3 1.2,1 1.2,1.8C45.3,56.528 44.5,57.328 43.4,57.328L43.4,57.328zM64.6,57.328c-0.8,0 -1.5,-0.5 -1.8,-1.2s-0.1,-1.5 0.4,-2.1c0.5,-0.5 1.4,-0.7 2.1,-0.4c0.7,0.3 1.2,1 1.2,1.8C66.5,56.528 65.6,57.328 64.6,57.328L64.6,57.328z"
        android:strokeWidth="1"
        android:strokeColor="#00000000" />
</vector>

وجوا فولد ال layout 
 ملف واحد اسمه activity_main.xml
 
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp"
    android:background="#F5F5F5">

    <!-- Header -->
    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="horizontal"
        android:gravity="center_vertical"
        android:padding="16dp"
        android:background="@drawable/header_background"
        android:layout_marginBottom="24dp">

        <ImageView
            android:layout_width="48dp"
            android:layout_height="48dp"
            android:src="@drawable/ic_shield"
            android:layout_marginEnd="16dp" />

        <LinearLayout
            android:layout_width="0dp"
            android:layout_height="wrap_content"
            android:layout_weight="1"
            android:orientation="vertical">

            <TextView
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="Android Protector"
                android:textSize="24sp"
                android:textStyle="bold"
                android:textColor="#FFFFFF" />

            <TextView
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="Advanced App Protection"
                android:textSize="14sp"
                android:textColor="#E0E0E0" />

        </LinearLayout>

    </LinearLayout>

    <!-- Main Content -->
    <ScrollView
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="1">

        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="vertical">

            <!-- Assets Protection Card -->
            <androidx.cardview.widget.CardView
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:layout_marginBottom="16dp"
                app:cardCornerRadius="12dp"
                app:cardElevation="4dp"
                android:background="#FFFFFF">

                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:orientation="vertical"
                    android:padding="20dp">

                    <LinearLayout
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:orientation="horizontal"
                        android:gravity="center_vertical"
                        android:layout_marginBottom="16dp">

                        <ImageView
                            android:layout_width="32dp"
                            android:layout_height="32dp"
                            android:src="@drawable/ic_assets"
                            android:layout_marginEnd="12dp" />

                        <TextView
                            android:layout_width="wrap_content"
                            android:layout_height="wrap_content"
                            android:text="Assets Protection"
                            android:textSize="20sp"
                            android:textStyle="bold"
                            android:textColor="#333333" />

                    </LinearLayout>

                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Protect app assets using AES encryption and file splitting"
                        android:textSize="14sp"
                        android:textColor="#666666"
                        android:layout_marginBottom="20dp" />

                    <!-- File Selection -->
                    <LinearLayout
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:orientation="horizontal"
                        android:layout_marginBottom="16dp">

                        <Button
                            android:id="@+id/btnSelectApp"
                            android:layout_width="0dp"
                            android:layout_height="48dp"
                            android:layout_weight="1"
                            android:text="Select App"
                            android:textColor="#FFFFFF"
                            android:background="@drawable/button_primary"
                            android:layout_marginEnd="8dp" />

                        <Button
                            android:id="@+id/btnBrowseFiles"
                            android:layout_width="0dp"
                            android:layout_height="48dp"
                            android:layout_weight="1"
                            android:text="Browse Files"
                            android:textColor="#2196F3"
                            android:background="@drawable/button_outline"
                            android:layout_marginStart="8dp" />

                    </LinearLayout>

                    <!-- Selected File Display -->
                    <LinearLayout
                        android:id="@+id/layoutSelectedFile"
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:orientation="horizontal"
                        android:background="@drawable/file_background"
                        android:padding="12dp"
                        android:layout_marginBottom="16dp"
                        android:visibility="gone">

                        <ImageView
                            android:layout_width="24dp"
                            android:layout_height="24dp"
                            android:src="@drawable/ic_file"
                            android:layout_marginEnd="12dp" />

                        <TextView
                            android:id="@+id/tvSelectedFile"
                            android:layout_width="0dp"
                            android:layout_height="wrap_content"
                            android:layout_weight="1"
                            android:text="No file selected"
                            android:textSize="14sp"
                            android:textColor="#333333" />

                        <ImageView
                            android:id="@+id/ivRemoveFile"
                            android:layout_width="24dp"
                            android:layout_height="24dp"
                            android:src="@drawable/ic_close"
                            android:background="?attr/selectableItemBackgroundBorderless"
                            android:padding="4dp" />

                    </LinearLayout>

                    <!-- Protection Options -->
                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Protection Options:"
                        android:textSize="16sp"
                        android:textStyle="bold"
                        android:textColor="#333333"
                        android:layout_marginBottom="12dp" />

                    <CheckBox
                        android:id="@+id/cbAssetsProtection"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Encrypt Assets"
                        android:textSize="14sp"
                        android:checked="true"
                        android:layout_marginBottom="8dp" />

                    <CheckBox
                        android:id="@+id/cbFileSplitting"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Split Files"
                        android:textSize="14sp"
                        android:checked="true"
                        android:layout_marginBottom="8dp" />

                    <CheckBox
                        android:id="@+id/cbAutoRestore"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Auto Recovery"
                        android:textSize="14sp"
                        android:checked="true"
                        android:layout_marginBottom="20dp" />

                    <!-- Action Button -->
                    <Button
                        android:id="@+id/btnStartProtection"
                        android:layout_width="match_parent"
                        android:layout_height="56dp"
                        android:text="Start Protection"
                        android:textSize="16sp"
                        android:textStyle="bold"
                        android:textColor="#FFFFFF"
                        android:background="@drawable/button_success"
                        android:enabled="false" />

                </LinearLayout>

            </androidx.cardview.widget.CardView>

            <!-- Progress Card -->
            <androidx.cardview.widget.CardView
                android:id="@+id/cardProgress"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:layout_marginBottom="16dp"
                app:cardCornerRadius="12dp"
                app:cardElevation="4dp"
                android:visibility="gone">

                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:orientation="vertical"
                    android:padding="20dp">

                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Processing..."
                        android:textSize="18sp"
                        android:textStyle="bold"
                        android:textColor="#333333"
                        android:layout_marginBottom="16dp" />

                    <ProgressBar
                        android:id="@+id/progressBar"
                        style="?android:attr/progressBarStyleHorizontal"
                        android:layout_width="match_parent"
                        android:layout_height="8dp"
                        android:layout_marginBottom="12dp"
                        android:progress="0"
                        android:max="100" />

                    <TextView
                        android:id="@+id/tvProgressStatus"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Starting process..."
                        android:textSize="14sp"
                        android:textColor="#666666" />

                </LinearLayout>

            </androidx.cardview.widget.CardView>

            <!-- Results Card -->
            <androidx.cardview.widget.CardView
                android:id="@+id/cardResults"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                app:cardCornerRadius="12dp"
                app:cardElevation="4dp"
                android:visibility="gone">

                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:orientation="vertical"
                    android:padding="20dp">

                    <LinearLayout
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:orientation="horizontal"
                        android:gravity="center_vertical"
                        android:layout_marginBottom="16dp">

                        <ImageView
                            android:id="@+id/ivResultIcon"
                            android:layout_width="32dp"
                            android:layout_height="32dp"
                            android:src="@drawable/ic_success"
                            android:layout_marginEnd="12dp" />

                        <TextView
                            android:id="@+id/tvResultTitle"
                            android:layout_width="wrap_content"
                            android:layout_height="wrap_content"
                            android:text="Protection completed successfully!"
                            android:textSize="18sp"
                            android:textStyle="bold"
                            android:textColor="#4CAF50" />

                    </LinearLayout>

                    <TextView
                        android:id="@+id/tvResultDetails"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="Files have been encrypted and split successfully"
                        android:textSize="14sp"
                        android:textColor="#666666"
                        android:layout_marginBottom="16dp" />

                    <Button
                        android:id="@+id/btnSaveResults"
                        android:layout_width="match_parent"
                        android:layout_height="48dp"
                        android:text="Save Results"
                        android:textColor="#FFFFFF"
                        android:background="@drawable/button_primary" />

                </LinearLayout>

            </androidx.cardview.widget.CardView>

        </LinearLayout>

    </ScrollView>

</LinearLayout>


افهم كويس وقلي عشان عايزك حاجة
