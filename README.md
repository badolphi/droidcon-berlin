This is material accompanying my Droidcon Berlin workshop "How to attack (and secure) an Android app: An introduction".

In this repo, you find `app.apk`, which is a simple app that asks for a password and verifies it both in Java and in native code. We will use this app for the demonstrations.

To be able to run the app, you need an Android device. For some demonstrations, root access is required. You can run them all on a physical device with root access. But probably the easiest thing to do is to install Android Studio from here: https://developer.android.com/studio and then install an emulator that has root access. You will need to setup a device with an emulator without Google Play to be able to get root access. Also, you want to use an emulator that matches the architecture of your CPU for optimal performance. In the demonstrations, I will assume that we are using an ARM64 emulator so you might have to make slight modifications if your are running on a different platform.

# Required tools
* jadx: https://github.com/skylot/jadx
* Ghidra: https://github.com/NationalSecurityAgency/ghidra

# Reverse engineering
Here, I show how you can reverse engineer the app to find out what the correct passwords are.

## Java code

You will need a tool called jadx, which you can download from here: https://github.com/skylot/jadx.

You can launch the tool by invoking `jadx-gui` or `jadx-gui.bat`.

You can then load the app into it and explore the Java code.

The interesting code is in the class `no.promon.droidcon.MainActivity` where we find the `checkPasswordJava` method that contains the password.

## Native code
As a simple way to get the password from the native library, you can just invoke the `strings` command on the library: `unzip -p app.apk lib/arm64-v8a/libdroidcon.so | strings`.

But you can also use Ghidra (https://github.com/NationalSecurityAgency/ghidra) to disassemble the code of the native library.

The interesting function is `Java_no_promon_droidcon_MainActivity_checkPasswordNative` and you should be able to see the password that it checks.

# Repackaging
Here, I show how to modify the app on disk in different ways to accept any password.

## Java code
To repackage the Java code of the app, you need to download apktool from here: https://bitbucket.org/iBotPeaches/apktool/downloads.

To make the Java check always succeed, perform the following steps:
* Find the location you want to modify using jadx, which we have already done. It's the `checkPasswordJava` method in the `no.promon.droidcon.MainActivity` class. Our goal is to always make it return `true`.
* Decompile the code of the app with apktool: `java -jar apktool.jar d --no-res app.apk`.
* Open the smali code of the `MainActivity` class: `app/smali/no/promon/droidcon/MainActivity.smali`.
* If you want to learn more about the Dalvik bytecode, you can check here: https://source.android.com/docs/core/runtime/dalvik-bytecode
* Find the code of the `checkPasswordJava` method and change it to:
```
.method private checkPasswordJava(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```
* This makes the method always return true.
* You then compile the app again: `java -jar apktool.jar b app/ -o app-patched.apk`.
* Finally, you have to zipalign: `zipalign -p -v 4 app-patched.apk app-aligned.apk`.
* And sign the app: `apksigner sign --ks $KEYSTORE --ks-key-alias $KEYSTORE_ALIAS --ks-pass pass:$KEYSTORE_PASS --out app-signed.apk app-aligned.apk`.
* And then you can install the app to check that your modifications work: `adb install app-signed.apk`.
* The app should now accept any password.

## Native code

We can patch the native library of the app with Ghidra. To do this, we first open the library of the architecture we want to patch in Ghidra. In this example, we use the ARM64 version. If you want to run the code, you should patch the architecture that matches your emulator.

You then open the function we want to patch (`Java_no_promon_droidcon_MainActivity_checkPasswordNative`).

You then right click on the first instruction of the function and select "Patch Instruction" and then you patch it to: `mov x0, #1`. Then you do the same with the second instruction and patch it to `ret`.

The app should now accept any password.

# Hooking
Here, I show how to modify the app in different ways to accept any password while it is running.

As a prerequisite to this, you have to install Frida on you computer: `pip install frida-tools`.

In addition, you have to install `frida-server` on your emulator:
* Download the latest version of `frida-server` (frida-server-xxx-android-arm64.xz) from here: https://github.com/frida/frida/releases.
* Unzip the file and push it to the emulator: `adb push frida-server-xxx-android-arm64 /data/local/tmp/frida`
* Make the file executable and run the server:
	* `adb shell`
	* `su`
	* `chmod +x /data/local/tmp/frida`
	* `/data/local/tmp/frida`

## Java code
To make the java check always succeed, perform the following steps:
* Find the location you want to modify using jadx.
	* In the class `no.promon.droidcon.MainActivity`, we find the `checkPasswordJava` method. Our goal is to always make it return true.
* Create a new file `java_hook.js` with the following content:
```js
Java.perform(function()
{
    var activity = Java.use("no.promon.droidcon.MainActivity");
    activity.checkPasswordJava.implementation = function (password)
    {
        console.log("Entered: " + password);
        return true;
    };
});
```
* Launch the app on the emulator.
* Run Frida on your computer to inject the hook: `frida -U -F -l java_hook.js`.
* The app should now accept any password for the Java check.

## Native code
To make the native check always succeed, perform the following steps:
* Find the location you want to modify using Ghidra.
	* You can find the `Java_no_promon_droidcon_MainActivity_checkPasswordNative` function that checks the password. Our goal is to always make it return true.
* Create a new file `native_hook.js` with the following content:
```js
var module = Process.findModuleByName("libdroidcon.so");
var address = module.findExportByName("Java_no_promon_droidcon_MainActivity_checkPasswordNative");

Interceptor.attach(address,
{
    onEnter: function (args)
    {
        var password = Java.cast(args[2], Java.use("java.lang.String"));
        console.log("Called: " + password);
    },
    onLeave: function(ret)
    {
        ret.replace(1);
    }
});
```
* Launch the app on the emulator.
* Run Frida on your computer to inject the hook: `frida -U -F -l native_hook.js`.
* The app should now accept any password for the native check.

# Debugging
Here, I show how to debug the app in different ways.

## Java code
As a prerequisite, you need ManifestEditor. You can find the source code here: https://github.com/WindySha/ManifestEditor. The latest release does not contain a required patch. So you need to build it yourself like so:

* `git clone https://github.com/WindySha/ManifestEditor.git`
* `cd ManifestEditor`
* `./gradlew build`

You then find the file built JAR file at: `lib/build/libs/ManifestEditor-1.0.2.jar`.

Now we can modify the app to insert the `android:debuggable` property into the manifest: 
* `java -jar ManifestEditor-1.0.2.jar -d 1 app.apk -o app-patched.apk`
* `zipalign -p -v 4 app-patched.apk app-aligned.apk`
* `apksigner sign --ks $KEYSTORE --ks-key-alias $KEYSTORE_ALIAS --ks-pass pass:$KEYSTORE_PASS --out app-signed.apk app-aligned.apk`

In addition, open the app in jadx and go to "File" -> "Save all" and to save the decompiled Java code of the app.

You can then launch Android Studio and then go to "File" -> "Profile or Debug APK" and open the `app-signed.apk` file you just created.

Then navigate to the `MainActivity` class. Here you will see that you only see the smali code of the app and not the Java code that is required for placing breakpoints. You can fix this by selecting "Attach Kotlin/Java Sources..." and select the folder with the decompiled Java sources you just exported. Now you are able to debug the app and place breakpoints in it.

## Native code
As a prerequisite of debugging native code, you need to find `gdb` on your computer. You find it in the `prebuild/<computer platform>/bin/` folder of older Android NDKs. I have obtained mine from version `r21e`.

Also, you need to install `gdbserver` to your emulator. You find it in the `prebuild/android-arm64/bin/` folder of older Android NDKs. I have obtained mine from version `r21e`. You install it like so:
* `adb push gdbserver /data/local/tmp/`
* `adb shell`
* `su`
* `chmod +x /data/local/tmp/gdbserver`

You then run your application, get its pid and attach gdbserver to it:
* `adb shell`
* `ps -A | grep droidcon`
* `/data/local/tmp/gdbserver :5039 --attach <pid>`

On your computer, you have to forward the port and then connect to the server:
* `adb forward tcp:5039 tcp:5039`
* `gdb -ex "target remote :5039"`

Now you can set a breakpoint on the interesting function:
* `break Java_no_promon_droidcon_MainActivity_checkPasswordNative`

Disable stopping for signals:
* `handle all nostop`
* `handle all noprint`

Continue the application:
* `c`

When you now press the "Check Native" button in the app, your breakpoint will be hit.

You can disassemble the code: `disas`.

You can put another breakpoint on the `ret` instruction when the function returns and then continue the app:
* `break *<address of ret insn>`
* `c`

And finally, you can change the return value and continue the app:
* `set $x0=1`
* `c`
