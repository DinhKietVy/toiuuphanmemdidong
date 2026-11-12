# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# ---------------------------------------------------------------- MobiTive (M9)
# TensorFlow Lite: Java classes are called from native code (JNI).
-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**

# apk-parser: binary-XML/resource parsing uses reflection on its own classes.
-keep class net.dongliu.apk.parser.** { *; }
-dontwarn net.dongliu.apk.parser.**
-dontwarn javax.annotation.**

# Readable crash stack traces for bug reports.
-keepattributes SourceFile,LineNumberTable
