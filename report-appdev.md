## 1. helloworld

### Objective

Create an Android app that prints the string **`hello-world-mobisec-edition`** to the system log using the tag **`MOBISEC`**.

### Solution Idea

The grading system launches the APK and checks the system log output.  
To satisfy the requirement reliably, the log message is emitted at application startup inside the main Activity lifecycle method (`onCreate`). This guarantees the message is produced immediately when the app is started by the evaluator, without needing any user interaction.

### Implementation (MainActivity)

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.os.Bundle
import android.util.Log

class MainActivity : Activity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    // Required output for the challenge
    Log.i("MOBISEC", "hello-world-mobisec-edition")

    // No UI is needed
    finish()
  }
}
```

### Flag

```
 MOBISEC : hello-world-mobisec-edition
```

## 2. justlisten

### Objective

Receive the flag from a broadcast intent with action **`com.mobisec.intent.action.FLAG_ANNOUNCEMENT`**.  
The flag is contained in the intent extras under the key **`"flag"`**, and must be printed to the system log.

### Solution Idea

The target environment announces the flag via a broadcast intent.  
To capture it, the app registers a `BroadcastReceiver` that listens for the specific action. Because newer Android versions enforce stricter broadcast rules, the receiver is registered dynamically at runtime and explicitly marked as **exported** (so it can receive broadcasts coming from outside the app). When the broadcast arrives, the receiver extracts the `"flag"` extra and prints it to Logcat using tag `MOBISEC`.

### Implementation

**MainActivity**

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.core.content.ContextCompat

class MainActivity : Activity() {

    companion object {
        private const val ACTION_FLAG = "com.mobisec.intent.action.FLAG_ANNOUNCEMENT"
        private const val KEY_FLAG = "flag"
        private const val TAG = "MOBISEC"
    }

    private val flagReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != ACTION_FLAG) return
            val flag = intent.extras?.getString(KEY_FLAG) ?: return
            Log.i(TAG, flag)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Không cần UI
        Log.i(TAG, "ready")
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(ACTION_FLAG)

        if (Build.VERSION.SDK_INT >= 33) {
            ContextCompat.registerReceiver(
                this,
                flagReceiver,
                filter,
                ContextCompat.RECEIVER_EXPORTED
            )
        } else {
            @Suppress("DEPRECATION")
            ContextCompat.registerReceiver(
                this,
                flagReceiver,
                filter,
                ContextCompat.RECEIVER_EXPORTED
            )
        }
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(flagReceiver)
    }
}


```

### Flag

```
MOBISEC{not_sure_Ive_heard_well_what_did_ya_say?!?}
```

## 3. reachingout

### Objective

Connect to an HTTP server available from inside the emulator at **`10.0.2.2:31337`**, solve the server’s simple math challenge, submit the answer back to the server, and print the resulting **flag** to the system log.

### Solution Idea

In the Android emulator, the special IP address `10.0.2.2` points to the host machine. The challenge exposes an HTTP service on `10.0.2.2:31337`.  
When requesting `/flag`, the server responds with an HTML form containing a math question and hidden fields (`val1`, `oper`, `val2`). The app must:

1. Perform an HTTP **GET** to `http://10.0.2.2:31337/flag` to retrieve the HTML form.
2. Parse the hidden values (`val1`, `oper`, `val2`) from the HTML.
3. Compute the answer and send it back via an HTTP **POST** to `/flag` as `application/x-www-form-urlencoded` with fields:
   - `answer`, `val1`, `oper`, `val2`
4. Extract `flag{...}` from the server response and print it to Logcat using tag `MOBISEC`.

This is implemented at app startup so the evaluator only needs to launch the APK once.

### Required Manifest Settings

The app needs Internet access and must allow HTTP (cleartext) traffic:

**AndroidManifest.xml**

```xml
<uses-permission android:name="android.permission.INTERNET" />

<application
    android:usesCleartextTraffic="true"
    ... >
</application>
```

**MainActivity**

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.os.Bundle
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class MainActivity : Activity() {

  private val TAG = "MOBISEC"
  private val BASE = "http://10.0.2.2:31337"

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    Log.i(TAG, "start reachingout")

    val t = Thread {
      try {
        val html = httpGet("$BASE/flag")
        Log.i(TAG, "got form")

        val val1 = extractHidden(html, "val1")?.toLongOrNull()
        val val2 = extractHidden(html, "val2")?.toLongOrNull()
        val oper = extractHidden(html, "oper")

        if (val1 == null || val2 == null || oper.isNullOrBlank()) {
          Log.i(TAG, "parse failed")
          Log.i(TAG, html.take(200))
          return@Thread
        }

        val ans = when (oper.trim()) {
          "+" -> val1 + val2
          "-" -> val1 - val2
          "*", "x", "X" -> val1 * val2
          "/" -> if (val2 != 0L) val1 / val2 else 0L
          else -> 0L
        }

        Log.i(TAG, "computed: $val1 $oper $val2 = $ans")

        val body = formBody(
          "answer" to ans.toString(),
          "val1" to val1.toString(),
          "oper" to oper,
          "val2" to val2.toString(),
        )

        val resp = httpPost("$BASE/flag", body)
        // Log response (có thể chứa flag)
        Regex("""flag\{[^}]+\}""", RegexOption.IGNORE_CASE).find(resp)?.let {
          Log.i(TAG, it.value) // <-- FLAG ở đây
        } ?: run {
          Log.i(TAG, "no flag found, resp head: " + resp.take(200))
        }

      } catch (e: Exception) {
        Log.e(TAG, "err=${e.message}", e)
      }
    }

    t.start()
    t.join(5000) // chờ để grader kịp lấy log
    Log.i(TAG, "done")
  }

  private fun extractHidden(html: String, name: String): String? {
    val re = Regex("""name\s*=\s*["']$name["'][^>]*value\s*=\s*["']([^"']*)["']""", RegexOption.IGNORE_CASE)
    return re.find(html)?.groupValues?.get(1)
  }

  private fun httpGet(url: String): String {
    val conn = (URL(url).openConnection() as HttpURLConnection).apply {
      requestMethod = "GET"
      connectTimeout = 3000
      readTimeout = 3000
    }
    return conn.inputStream.use { inp ->
      BufferedReader(InputStreamReader(inp)).readText()
    }
  }

  private fun httpPost(url: String, body: String): String {
    val conn = (URL(url).openConnection() as HttpURLConnection).apply {
      requestMethod = "POST"
      connectTimeout = 3000
      readTimeout = 3000
      doOutput = true
      setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
    }
    conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

    val stream = try { conn.inputStream } catch (_: Exception) { conn.errorStream }
    return stream.use { inp ->
      BufferedReader(InputStreamReader(inp)).readText()
    }
  }

  private fun formBody(vararg pairs: Pair<String, String>): String =
    pairs.joinToString("&") { (k, v) ->
      "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
    }
}

```

### Flag

```
MOBISEC{I_was_told_by_liars_that_http_queries_were_easy}
```

## 4. justask

### Objective

There is a target application `com.mobisec.justask` that contains **four activities**, each holding one part of the flag.  
If we “ask them nicely”, each activity returns an `Intent` containing its fragment of the flag.  
The goal is to query all four activities, recover all fragments, and reconstruct the final flag.

### Analysis of the Target App

From the provided manifest of the target app:

```xml
<activity android:name=".PartOne" android:exported="true"/>

<activity android:name=".PartTwo">
    <intent-filter>
        <action android:name="com.mobisec.intent.action.JUSTASK"/>
    </intent-filter>
</activity>

<activity android:name=".PartThree" android:exported="true"/>

<activity android:name=".PartFour">
    <intent-filter>
        <action android:name="com.mobisec.intent.action.JUSTASKBUTNOTSOSIMPLE"/>
    </intent-filter>
</activity>
```

**The core idea is:**

The app com.mobisec.justask exposes four activities: PartOne, PartTwo, PartThree, PartFour.

- PartOne and PartThree are exported and can be started explicitly via ComponentName.

- PartTwo and PartFour are reachable via custom intent actions, but can also be called directly by explicit component.

- Each activity returns an Intent with extras; some parts of the flag are stored directly in extras (e.g. keys like flag, hiddenFlag), and some are hidden inside nested Bundle objects (e.g. under a key like follow).

Instead of guessing a single extra key, I implemented a generic “probe” client that:

1. Starts all four Part\* activities via startActivityForResult, using explicit ComponentName.

2. In onActivityResult, logs the result intent and:

   - Prints all top-level extras (key–value pairs).

   - If an extra contains a nested Bundle (e.g. key "follow"), recursively traverses that bundle and logs all nested keys and values as well.

3. Reads the flag fragments from Logcat and concatenates them manually into the final flag.

This approach uses the manifest to determine how to talk to each activity, and then uses exhaustive inspection of the returned intents to reveal all hidden data.

### Implementation

**MainActivity**

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.os.Bundle as AndroidBundle

class MainActivity : Activity() {

    private val TAG = "MOBISEC"
    private val REQ = 1    // same requestCode for all activities

    private var depthCounter = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.e(TAG, "onCreate (justask client)")

        // PartTwo
        val partTwo = Intent().apply {
            component = ComponentName(
                "com.mobisec.justask",
                "com.mobisec.justask.PartTwo"
            )
        }
        startActivityForResult(partTwo, REQ)
        Log.e(TAG, "PartTwo started")

        // PartOne
        val partOne = Intent().apply {
            component = ComponentName(
                "com.mobisec.justask",
                "com.mobisec.justask.PartOne"
            )
        }
        startActivityForResult(partOne, REQ)
        Log.e(TAG, "PartOne started")

        // PartThree
        val partThree = Intent().apply {
            component = ComponentName(
                "com.mobisec.justask",
                "com.mobisec.justask.PartThree"
            )
        }
        startActivityForResult(partThree, REQ)
        Log.e(TAG, "PartThree started")

        // PartFour
        val partFour = Intent().apply {
            component = ComponentName(
                "com.mobisec.justask",
                "com.mobisec.justask.PartFour"
            )
        }
        startActivityForResult(partFour, REQ)
        Log.e(TAG, "PartFour started")
    }

    @Deprecated("Sufficient for this challenge environment")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        Log.e(TAG, "onActivityResult called")
        Log.e(TAG, "requestCode=$requestCode resultCode=$resultCode data=$data")

        if (data == null) return

        val bundle: AndroidBundle? = data.extras
        if (bundle != null) {
            // Log all top-level extras
            for (key in bundle.keySet()) {
                val v = bundle.get(key)
                Log.e(TAG, "EXTRA key=$key : ${v ?: "NULL"}")

                // Some returns store nested data under "follow"
                if (key == "follow" && v is AndroidBundle) {
                    depthCounter = 0
                    dumpNestedBundle(v)
                }
            }
        }
    }

    // Recursively explore nested Bundles and log all keys/values
    private fun dumpNestedBundle(bundle: AndroidBundle) {
        Log.e(TAG, "bundleMaze depth=$depthCounter")
        depthCounter++

        for (k in bundle.keySet()) {
            val v = bundle.get(k)
            Log.e(TAG, "BUNDLE key=$k : ${v ?: "NULL"}")
            if (v is AndroidBundle && depthCounter < 10) {
                dumpNestedBundle(v)
            }
        }
    }
}

```

From the Logcat output produced by the client in the grading environment, the following fragments were obtained:

- MOBISEC{Ive

- _asked_and_

- I_got_the_f

- lag_how_nice!} (hidden inside a nested Bundle under key theywillneverfindthisfourthpart)

### Flag

```
MOBISEC{Ive_asked_and_I_got_the_flag_how_nice!}
```

## 5. filehasher

### Objective

Provide an exported Android activity that computes the **SHA-256 hash** of a file specified by the challenge framework.  
The framework:

- starts our activity with the action **`com.mobisec.intent.action.HASHFILE`**,
- passes the file location in the **data URI** (`intent.getData()`),
- expects the SHA-256 hash of the file contents in **hexadecimal string** format, returned under the key **`"hash"`** in a result `Intent`.

If the hash returned by our app matches the expected value, the framework prints the flag in the system log.

### Solution Idea

The app acts as a small “hashing service” exposed through an activity:

1. **Exported hashing activity**  
   Define an activity (e.g. `HashFileActivity`) with an intent filter for  
   `com.mobisec.intent.action.HASHFILE`. This makes it discoverable and callable by the challenge app.  
   Since the file is on the SDCard, the app also requests `READ_EXTERNAL_STORAGE`.

2. **Receive the file URI**  
   When the activity is launched, the framework puts the file location in the intent’s data field:  
   `val uri = intent.data`.  
   Instead of trying to parse a raw path string, the app uses `contentResolver.openInputStream(uri)` to obtain an `InputStream` for the file.

3. **Compute SHA-256 of the file**  
   The file is read in chunks (e.g. 4 KB) and fed into a `MessageDigest` configured for `"SHA-256"`.  
   After all bytes are processed, the digest is converted to a lowercase hexadecimal string, with no separators, which is exactly the format expected by the checker.

4. **Return the hash via result Intent**  
   The app creates a result `Intent`, puts the computed hash under the `"hash"` key, sets `RESULT_OK`, and finishes.  
   The challenge framework compares this string to the expected value and, on success, prints the flag to Logcat.

### Implementation (HashFileActivity)

**HashFileActivity**

```
package com.example.helloworldmobisec

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import java.io.InputStream
import java.security.MessageDigest

class HashFileActivity : Activity() {

    private val TAG = "MOBISEC"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val fileUri: Uri? = intent?.data
        if (fileUri == null) {
            Log.e(TAG, "No data URI in intent")
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        // Do the hashing off the main thread
        Thread {
            try {
                val hashHex = calcSha256FromUri(fileUri)

                val resultIntent = Intent().apply {
                    putExtra("hash", hashHex)
                }
                setResult(RESULT_OK, resultIntent)
                Log.i(TAG, "hash=$hashHex")
            } catch (e: Exception) {
                Log.e(TAG, "Error hashing file: ${e.message}", e)
                setResult(RESULT_CANCELED)
            } finally {
                finish()
            }
        }.start()
    }

    private fun calcSha256FromUri(uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")

        val input: InputStream? = contentResolver.openInputStream(uri)
        input.use { stream ->
            requireNotNull(stream) { "InputStream is null" }
            val buffer = ByteArray(4096)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }

        val bytes = digest.digest()
        // Convert to lowercase hex
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

```

The challenge framework starts HashFileActivity with action com.mobisec.intent.action.HASHFILE and a data URI pointing to a file on external storage.

The activity reads the file via ContentResolver, computes its SHA-256 hash, and returns it under the "hash" extra in a result intent.

When the returned hash matches the expected value, the filehasher challenge prints the flag to the system log, which can then be collected as the final answer.

### Flag

```
MOBISEC{Was_it_known_that_these_one_way_functions_give_you_back_flags?}
```

## 6. whereareyou

### Objective

Implement an exported Android **Service** that responds to location requests.
The system discovers the service via an intent filter with action **`com.mobisec.intent.action.GIMMELOCATION`**, starts it using `startService()`, and expects the app to broadcast back the **current Location** as a `Location` object.

If the returned location matches the location set by the test environment (which changes at runtime), the flag is printed in the logs.

### Solution Idea

The challenge is based on Android IPC and location updates:

- A custom service (`GimmeLocationService`) is declared **exported** with an intent filter for `com.mobisec.intent.action.GIMMELOCATION`, allowing the external test harness to start it.
- The service continuously tracks the “current” location using `LocationManager.requestLocationUpdates(...)` and stores the latest value.
- Each time the test harness starts the service, the service immediately sends a broadcast intent with action
  **`com.mobisec.intent.action.LOCATION_ANNOUNCEMENT`** and includes the latest `Location` object in the intent extras under key **`"location"`**.
- Permission checks (`checkSelfPermission`) are used to avoid `SecurityException` on modern Android versions.

### Implementation

**AndroidManifest.xml**

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>

<application ...>
    <service
        android:name=".GimmeLocationService"
        android:exported="true">
        <intent-filter>
            <action android:name="com.mobisec.intent.action.GIMMELOCATION"/>
        </intent-filter>
    </service>
</application>
```

**GimmeLocationService**

```kotlin
package com.example.helloworldmobisec

import android.Manifest
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Bundle
import android.os.IBinder
import android.util.Log

class GimmeLocationService : Service() {

    companion object {
        private const val TAG = "MOBISEC"
        private const val ACTION_REPLY = "com.mobisec.intent.action.LOCATION_ANNOUNCEMENT"
    }

    private lateinit var lm: LocationManager
    @Volatile private var lastLoc: Location? = null

    private val listener = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            lastLoc = location
        }
        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}
        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
    }

    private fun hasLocPerm(): Boolean {
        val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val coarse = checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        return fine || coarse
    }

    override fun onCreate() {
        super.onCreate()
        lm = getSystemService(LOCATION_SERVICE) as LocationManager

        if (!hasLocPerm()) return

        try {
            if (lm.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0L, 0f, listener)
            }
        } catch (_: SecurityException) {}

        try {
            if (lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                lm.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 0L, 0f, listener)
            }
        } catch (_: SecurityException) {}
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // mỗi lần hệ thống gọi startService -> trả location hiện tại
        val loc = getBestLocation()
        if (loc != null) {
            val out = Intent(ACTION_REPLY).putExtra("location", loc)
            sendBroadcast(out)
            Log.i(TAG, "sent location: ${loc.latitude},${loc.longitude}")
        } else {
            Log.i(TAG, "no location yet")
        }

        stopSelf(startId)
        return START_NOT_STICKY
    }

    private fun getBestLocation(): Location? {
        lastLoc?.let { return it }
        if (!hasLocPerm()) return null

        try { lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)?.let { return it } }
        catch (_: SecurityException) {}

        try { lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)?.let { return it } }
        catch (_: SecurityException) {}

        return null
    }

    override fun onDestroy() {
        try {
            if (hasLocPerm()) lm.removeUpdates(listener)
        } catch (_: SecurityException) {}
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

```

### Flag

```
MOBISEC{Where_are_you_bro?_Will_not_tell_anybody_I_swear}
```

## 7. jokeprovider

### Objective

Read data from the target app’s exported Content Provider and build the flag by:

1. selecting all jokes authored by **`"reyammer"`**, and
2. concatenating their **`joke`** strings in order.

### Solution Idea

The target application exposes an **exported Content Provider** with authority `com.mobisec.provider.Joke` and a public URI:
`content://com.mobisec.provider.Joke/jokes`.

Because it is exported, our app can query it through Android’s `ContentResolver`.  
We query the provider with a SQL-like selection `author=?` (with argument `reyammer`) so we only retrieve the required rows. From the returned cursor, we read the `joke` column and append each value to a `StringBuilder`. The final concatenated string is the flag and is printed to Logcat with tag `MOBISEC`.

### Implementation

**Manifest**
No special permissions are required; only a launcher activity is needed.

**MainActivity**

```kotlin
ppackage com.example.helloworldmobisec

import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.util.Log

class MainActivity : Activity() {

    private val TAG = "MOBISEC"
    private val URI = Uri.parse("content://com.mobisec.provider.Joke/jokes")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Thread {
            try {
                val selection = "author=?"
                val selectionArgs = arrayOf("reyammer")

                // projection = columns, which need to be retrieved
                val projection = arrayOf("joke")

                val sb = StringBuilder()
                contentResolver.query(
                    URI,
                    projection,
                    selection,
                    selectionArgs,
                    null // sortOrder: to null to keep the order returned by the provider
                )?.use { c ->
                    val idx = c.getColumnIndex("joke")
                    while (c.moveToNext()) {
                        sb.append(c.getString(idx))
                    }
                }

                val flag = sb.toString()
                Log.i(TAG, flag)
            } catch (e: Exception) {
                Log.e(TAG, "err=${e.message}", e)
            }
        }.start()

        finish()
    }
}
```

### Flag

```
MOBISEC{lol_roftl_ahahah_:D_REYAMMER_TELLS_THE_BEST_JOKES!}
```

## 8. unbindable

### Objective

Interact with the target app’s **exported service** and retrieve the flag via IPC.  
The flag must be printed to the system log.

### Solution Idea

The target app exposes an exported service `com.mobisec.unbindable.UnbindableService`. The service uses Android’s **Messenger**-based IPC: clients register themselves by sending a `Message` with `what = 1` (REGISTER) and setting `replyTo` to their own `Messenger`. After registration, the client requests the flag by sending a `Message` with `what = 4` (GET_FLAG), again with `replyTo` set.

When the service replies, it sends a `Message` with `what = 4` and includes a `Bundle` containing the key `"flag"`. In the provided service implementation, this `Bundle` is passed using `Message.obj` (not `Message.data`), so the client must read the flag from `msg.obj as Bundle`.

Finally, the app logs the flag with tag `MOBISEC` so the grading system can capture it.

### Implementation

Only a launcher activity is required. On Android 11+, package visibility can block cross-app service resolution, so we declare a `<queries>` entry for the target package.

**Manifest**

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <queries>
        <package android:name="com.mobisec.unbindable" />
    </queries>

    <application
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

    </application>
</manifest>

```

**MainActivity**

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.*
import android.util.Log

class MainActivity : Activity() {

    private val TAG: String = "MOBISEC"
    private val MSG_REGISTER_CLIENT: Int = 1
    private val MSG_GET_FLAG: Int = 4

    private var serviceMessenger: Messenger? = null

    private val incomingHandler: Handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            if (msg.what == MSG_GET_FLAG) {
                // IMPORTANT: target service sends Bundle via Message.obj
                val bundleFromObj: Bundle? = msg.obj as? Bundle
                val flag: String? =
                    bundleFromObj?.getString("flag")
                        ?: msg.data?.getString("flag")

                if (!flag.isNullOrBlank()) {
                    Log.i(TAG, flag)
                } else {
                    Log.i(TAG, "No flag in reply")
                }

                try { unbindService(conn) } catch (_: Exception) {}
                finish()
            } else {
                super.handleMessage(msg)
            }
        }
    }

    private val clientMessenger: Messenger = Messenger(incomingHandler)

    private val conn: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            serviceMessenger = Messenger(binder)

            val m1: Message = Message.obtain(null, MSG_REGISTER_CLIENT)
            m1.replyTo = clientMessenger
            serviceMessenger?.send(m1)

            val m2: Message = Message.obtain(null, MSG_GET_FLAG)
            m2.replyTo = clientMessenger
            serviceMessenger?.send(m2)
        }

        override fun onServiceDisconnected(name: ComponentName) {
            serviceMessenger = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val i: Intent = Intent().apply {
            component = ComponentName(
                "com.mobisec.unbindable",
                "com.mobisec.unbindable.UnbindableService"
            )
        }

        val ok: Boolean = bindService(i, conn, Context.BIND_AUTO_CREATE)
        if (!ok) {
            Log.i(TAG, "bindService failed")
            finish()
        }
    }
}
```

### Flag

```
MOBISEC{please_respect_my_will_you_shall_not_bind_me_my_friend}
```

## 9. serialintent

### Objective

Obtain the flag from an exported activity in the target app. The target returns a `Serializable` object in the result intent; the flag must be extracted and printed to the system log.

### Solution Idea

The target app exposes an exported activity `SerialActivity`. When started, it creates a `FlagContainer` object (which implements `Serializable`) and returns it via `setResult(...)` in the intent extra `"flag"`.

`FlagContainer` does not directly expose the flag as a public field. Instead, it stores:

- `parts`: an array of base64 fragments
- `perm`: a permutation describing the correct order

A private method `getFlag()` reconstructs the correct base64 string, decodes it, and returns the final flag.

To extract the flag, our app:

1. Starts the target exported activity (`com.mobisec.serialintent.SerialActivity`) and receives the result intent.
2. Ensures deserialization works by providing a class with the **same fully-qualified name** as the target’s `FlagContainer`, i.e. `com.mobisec.serialintent.FlagContainer`.
3. Uses reflection to invoke the private method `getFlag()` on the returned object and logs the resulting string with tag `MOBISEC`.

### Implementation

**Manifest**

Only a launcher activity is required. On Android 11+, we also declare package visibility for the target package.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <queries>
        <package android:name="com.mobisec.serialintent" />
    </queries>

    <application
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

    </application>
</manifest>
```

**mainActivity**

```kotlin
package com.example.helloworldmobisec

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.util.Log
import com.mobisec.serialintent.FlagContainer

class MainActivity : Activity() {

    private val REQ: Int = 1337

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val i = Intent().apply {
            component = ComponentName(
                "com.mobisec.serialintent",
                "com.mobisec.serialintent.SerialActivity"
            )
        }
        startActivityForResult(i, REQ)
    }

    @Deprecated("Deprecated in Android 11+, but works for this CTF")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQ && resultCode == RESULT_OK) {
            try {
                val fc = data?.getSerializableExtra("flag") as? FlagContainer
                if (fc != null) {
                    val m = fc.javaClass.getDeclaredMethod("getFlag")
                    m.isAccessible = true
                    val flag = m.invoke(fc) as String
                    Log.i("MOBISEC", flag)
                } else {
                    Log.i("MOBISEC", "No FlagContainer in result")
                }
            } catch (e: Exception) {
                Log.i("MOBISEC", "ERR: ${e.message}")
            }
        }

        finish()
    }
}
```

**FlagContainer.java**

```java
package com.mobisec.serialintent;

import android.util.Base64;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.ArrayList;

public class FlagContainer implements Serializable {
    private String[] parts;
    private ArrayList<Integer> perm;

    public FlagContainer(String[] parts, ArrayList<Integer> perm) {
        this.parts = parts;
        this.perm = perm;
    }

    private String getFlag() {
        int n = parts.length;
        int i;
        String b64 = new String();
        for (i=0; i<n; i++) {
            b64 += parts[perm.get(i)];
        }
        byte[] flagBytes = Base64.decode(b64, Base64.DEFAULT);
        String flag = new String(flagBytes, Charset.defaultCharset());

        return flag;
    }
}
```

### Flag

```
MOBISEC{HOW_DID_YOU_DO_IT_THAT_WAS_SERIALLY_PRIVATE_STUFF1!!1!eleven!}
```
