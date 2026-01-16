# **1. Solution of babyrev**
## **Description of the problem**
This task provides us with an Android application package (babyrev.apk). We need to disassemble and analyze the source code and find the hidden flags within.
## **Solution Idea**
The solution idea: The `checkFlag` function checks if the input flag is true. Therefore, if the flag is true, it will satisfy all the function's conditions and will not return false. Based on those conditions, we will find each part of the flag that satisfies the condition and combine them to obtain the flag.
### Description Solution
1. We use jadx-gui to decompile the babyrev.apk package to obtain source code that is easier to analyze and understand.</br>
2. From the source code, we can see classes such as MainActivity, FlagChecker, and BuildConfig. Let's analyze these classes. </br>
* Let's check the main class first.</br>
  A section of code containing a function and variable name called 'flag' is particularly noteworthy.
    ```java
    checkFlag.setOnClickListener(new View.OnClickListener() { // from class: com.mobisec.babyrev.MainActivity.2
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    String msg;
                    int color;
                    String flag = flagWidget.getText().toString();
                    boolean result = FlagChecker.checkFlag(MainActivity.this, flag);
                    if (result) {
                        msg = "Valid flag!";
                        color = -16737536;
                    } else {
                        msg = "Invalid flag";
                        color = SupportMenu.CATEGORY_MASK;
                    }
                    resultWidget.setText(msg);
                    resultWidget.setTextColor(color);
                }
            });
    ```
    From this code snippet, we see that the FlagChecker class calls the checkFlag function and checks the flag. Therefore, let's examine the FlagChecker class next.
- Class FlagChecker </br>
From the code of the FlagChecker class, we can see that: The `checkFlag` function checks if the input flag is true. Therefore, if the flag is true, it will satisfy all the function's conditions and will not return false. Based on those conditions, we will find each part of the flag that satisfies the condition and combine them to obtain the flag.

    * Let's start with the first condition.
  ```java
  if (!flag.startsWith("MOBISEC{") || 
  new StringBuilder(flag).reverse().toString().charAt(0) != '}' || 
  flag.length() != 35 || !flag.toLowerCase().substring(8).startsWit ("this_is_") ||
  !new StringBuilder(flag).reverse().toString().toLowerCase().substring(1).startsWith(ctx.getString(R.string.last_part)) || 
  flag.charAt(17) != '_' || flag.charAt((int) (getY() * Math.pow(getX(), getY()))) != flag.charAt(((int) Math.pow(Math.pow(2.0d, 2.0d), 2.0d)) + 1) 
  || !bam(flag.toUpperCase().substring(getY() * getX() * getY(), (int) (Math.pow(getZ(), getX()) - 1.0d))).equals("ERNYYL") 
  || flag.toLowerCase().charAt(16) != 'a' || flag.charAt(16) != flag.charAt(26) 
  {
            return false;
  }
  // I will rewrite it to make it easier to read (simply pre-calculating the mathematical expressions and replacing the getX(), getY(), and getZ() functions that return constant values and ctx.getString(R.string.last_part) = ver_cis from  <string name="last_part">ver_cis</string>" and toLowerCase()).
  if (!flag.startsWith("MOBISEC{") || 
  new StringBuilder(flag).reverse().toString().charAt(0) != '}' ||
  flag.length() != 35 ||
  !flag.substring(8).startsWith("this_is_") ||
  !new StringBuilder(flag).reverse().toString().substring(1).startsWith("ver_cis")) ||
  flag.charAt(17) != '_' ||
  flag.charAt(24) != flag.charAt(17) ||
  !bam(flag.substring(18, 24)).equals("ERNYYL")||
  flag.charAt(16) != 'a' ||
  flag.charAt(16) != flag.charAt(26) ||
  flag.charAt(25) != flag.charAt(26) + 1) {
    ...
  }
  ```
    The flag structure table from the above condition (we have flag.length() != 35, so the flag will have a length of 35). </br>
    
    | Position  | Value          | Source                        |
    |---------- |----------------|-------------------------------|
    | 0-7       | MOBISEC{       | flag.startsWith("MOBISEC{")                  |
    | 8-15      | this_is_       | !flag.substring(8).startsWith("this_is_") |
    | 16        | a              | flag.charAt(16) != 'a' ||         |
    | 17        | _              | flag.charAt(17) != '_' ||                   |
    | 18-23     | ???            | !bam(flag.substring(18, 24)).equals("ERNYYL")|
    | 24        | _              |  flag.charAt(24) != flag.charAt(17) ||                |
    | 25        | b              | flag.charAt(25) != flag.charAt(26) + 1          |
    | 26        | a              | flag.charAt(16) != flag.charAt(26)                 |
    | 27-33     | sic_rev        | !new StringBuilder(flag).reverse().toString().substring(1).startsWith("ver_cis"))         |
    | 34        | }              |        new StringBuilder(flag).reverse().toString().charAt(0) != '}'                        |

    => Flag has the form: MOBISEC{this_is_a_??????_basic_rev}
    * Let's look at the bam function.</br>
  
    ```java
    private static String bam(String s) {
        String out = BuildConfig.FLAVOR;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'm') {
                c = (char) (c + '\r');
            } else if (c >= 'A' && c <= 'M') {
                c = (char) (c + '\r');
            } else if (c >= 'n' && c <= 'z') {
                c = (char) (c - '\r');
            } else if (c >= 'N' && c <= 'Z') {
                c = (char) (c - '\r');
            }
            out = out + c;
        }
        return out;
    }

    //A fairly simple and easy-to-understand function. bam function is actually just rot13 cipher. We can solve it ourselves or use a tool like https://rot13.com/
    ``` 
    => from condition !bam(flag.substring(18, 24)).equals("ERNYYL") , we have flag substring(18, 24) =  REALLY
    => Flag has the form: MOBISEC{this_is_a_REALLY_basic_rev} </br>
  
    * Let's look at the final condition to get the correct flag.</br>
  
    ```java
    String r = getR();
        return flag.substring(8, flag.length() - 1).matches(r); 
    // and funstion R.
    public static String getR() {
        String r = BuildConfig.FLAVOR;
        boolean upper = true;
        for (int i = 0; i < 26; i++) {
            r = upper ? r + "[A-Z_]" : r + "[a-z_]";
            upper = !upper;
        }
        return r;
    }
    //  flag.substring(8, flag.length() - 1) = this_is_a_REALLY_basic_rev
    //  The get() function returns a string r in the following format: [A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_]
    ```
  Now it's simple, just compare them to get the correct uppercase and lowercase letters: </br>
  **Complete flag:** MOBISEC{ThIs_iS_A_ReAlLy_bAsIc_rEv}

# **2.Solution of pincode**
## **Description of the problem**
Give me the PIN, I'll give you the flag. This task provides us with an Android application package (pincode.apk). We need to disassemble and analyze the source code. The Android app requires the user to enter a 6-digit PIN. If the PIN is valid. The application will send an HTTP request to the server:

https://challs.reyammer.io/pincode/<PIN>

The server will return the flag. The task is to find a valid PIN.

## **Solution Idea**
Analyzing the application's workflow
### 1. MainActivity

```java
final EditText pinWidget = (EditText) findViewById(R.id.pincode);
Button checkPin = (Button) findViewById(R.id.checkpin);
final TextView resultWidget = (TextView) findViewById(R.id.result);
```
The user enters and verifies the PIN code; if the PIN code is valid, the flag is returned.

```java 
public String getFlag(String pin) {
    String url = "https://challs.reyammer.io/pincode/" + pin;
    try {
        String ans = getUrlContent(url);
        return ans;
    } catch (FileNotFoundException e) {
        return "Too many requests, slow down. You can do at most 10 requests per minute.";
    } catch (Exception e2) {
        String ans2 = "Exception: " + Log.getStackTraceString(e2);
        Log.e("MOBISEC", "Exception: " + Log.getStackTraceString(e2));
        return ans2;
    }
}
```
This function retrieves the flag if the PIN is valid. The application will connect to the server: "https://challs.reyammer.io/pincode/" + PIN and retrieve the flag.</br>
Therefore, the goal is to retrieve the PIN code. Next, we will analyze the PinChecker class.
### 2. PinChecker
I will add comments to the code so that we can easily understand and crack it to get the PIN code.

```java 
class PinChecker {
    PinChecker() {
    }
    // method checkPin: return true(if pin is correct) or false (otherwise, it's incorrect)
    public static boolean checkPin(Context ctx, String pin) throws NoSuchAlgorithmException {
        if (pin.length() != 6) { //The PIN must be exactly 6 characters long.
            return false;
        }
        try {
            byte[] pinBytes = pin.getBytes(); //Convert the PIN to a byte array
            for (int i = 0; i < 25; i++) { // 25 outer loops
                for (int j = 0; j < 400; j++) { // Each loop: 400 MD5 cycles
                    MessageDigest md = MessageDigest.getInstance("MD5"); //a total of 10,000 MD5 counts
                    md.update(pinBytes);
                    byte[] digest = md.digest();
                    pinBytes = (byte[]) digest.clone();
                }
            }
            String hexPinBytes = toHexString(pinBytes); // convert the result to hex
            return hexPinBytes.equals("d04988522ddfed3133cc24fb6924eae9"); //Comparison with fixed hash: If it matches → PIN is valid.
        } catch (Exception e) {
            Log.e("MOBISEC", "Exception while checking pin");
            return false;
        }
    }

    public static String toHexString(byte[] bytes) { //  tohexstring fuction converts to hex 
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 255);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```
### 3. Solution idea
Since the PIN code is only 6 digits and can be repeated 10,000 times (MD5), we can brute-force the entire PIN space.

* `Script brute-force (Python)`

```python 
import hashlib
import itertools

# iterate over all 6-digit combinations
for combination in itertools.product(range(10), repeat=6):
    pin = ''.join(str(x) for x in combination).encode()
    for _ in range(25 * 400):
        m = hashlib.md5()
        m.update(pin)
        pin = m.digest()

    if pin.hex() == "d04988522ddfed3133cc24fb6924eae9":
        print("FOUND PIN:", ''.join(str(x) for x in combination))
        break
```
* `Output: 703958`

=> Contacting server using https://challs.reyammer.io/pincode/703958 we get out flag:

**Complete flag:** MOBISEC{local_checks_can_be_very_bad_for_security}

# **3.Solution of gnirts**
## **Description of the problem**
Gnirts is a challenge that requires skills in decompiling APK files and reading, understanding, and analyzing Java code logic to find the flag.
## **Solution Idea**
We use jadx-gui to decompile the application. Analyzing the Java code reveals that the application requires the user to enter a valid flag, and the entire flag checking process is performed on the client side of the Android application. Therefore, from the flag checking code, we can understand and find the parts of the flag and combine them to obtain the complete flag.</br>
`Analyzing the application's workflow`
### 1. MainActivity
```java
final EditText flagWidget = (EditText) findViewById(R.id.flag);
Button checkFlag = (Button) findViewById(R.id.checkflag);
 checkFlag.setOnClickListener(new View.OnClickListener() { // from class: com.mobisec.gnirts.MainActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String msg;
                int color;
                String flag = flagWidget.getText().toString();
                boolean result = FlagChecker.checkFlag(MainActivity.this, flag);
                if (result) {
                    msg = "Valid flag!";
                    color = -16737536;
                } else {
                    msg = "Invalid flag";
                    color = SupportMenu.CATEGORY_MASK;
                }
                resultWidget.setText(msg);
                resultWidget.setTextColor(color);
            }
        });
```
The user enters a flag and checks it. We see a FlagChecker class being called and used to check the flag.
### 2.FlagChecker

* Flag format
```java
class FlagChecker {
    FlagChecker() {
    }

    public static boolean checkFlag(Context ctx, String flag) {
        if (!flag.startsWith("MOBISEC{") || !flag.endsWith("}")) {
            return false;
        }
```
The flag must be in the following format: MOBISEC{'core'}. </br>
* Core flag
```java
String core = flag.substring(8, 40);
        if (core.length() != 32) {
            return false;
        }
```
The core is exactly 32 characters long, excluding {} </br>
* Separator character – foo() function
```java 
String[] ps = core.split(foo());
  public static String foo() {
        String s = "Vm0wd2QyVkZNVWRYV0docFVtMVNWVmx0ZEhkVlZscDBUVlpPVmsxWGVIbFdiVFZyVm0xS1IyTkliRmRXTTFKTVZsVmFWMVpWTVVWaGVqQTk=";
        for (int i = 0; i < 10; i++) {
            s = new String(Base64.decode(s, 0));
        }
        return s;
}
```
The foo() function performs Base64 decoding 10 times on a fixed string. After decoding, the result is the character: '-' </br>
=> `The core has the following structure:`  **ps0-ps1-ps2-ps3-ps4**
* Partial constraints
```java
    if (ps.length != 5 || !bim(ps[0]) || !bum(ps[2]) || !bam(ps[4])) {
        return false;
    }

    private static boolean bim(String s) {
        return s.matches("^[a-z]+$");
    }

    private static boolean bum(String s) {
        return s.matches("^[A-Z]+$");
    }

    private static boolean bam(String s) {
        return s.matches("^[0-9]+$");
    }
```
The core will have 5 parts. </br>
ps0: lowercase letters only [a-z]+$ </br>
ps2: only uppercase letters [A-Z]+$ </br>
ps4: only digits [0-9]+$ </br>

* Solve the conditions to find each part of the flag
```java
return sum == 180 && 
chars.size() == 1 && 
me(ctx, dh(gs(ctx.getString(R.string.ct1), ctx.getString(R.string.k1)), ps[0]), ctx.getString(R.string.t1)) && 
me(ctx, dh(gs(ctx.getString(R.string.ct2), ctx.getString(R.string.k2)), ps[1]), ctx.getString(R.string.t2)) && 
me(ctx, dh(gs(ctx.getString(R.string.ct3), ctx.getString(R.string.k3)), ps[2]), ctx.getString(R.string.t3)) && 
me(ctx, dh(gs(ctx.getString(R.string.ct4), ctx.getString(R.string.k4)), ps[3]), ctx.getString(R.string.t4)) && 
me(ctx, dh(gs(ctx.getString(R.string.ct5), ctx.getString(R.string.k5)), ps[4]), ctx.getString(R.string.t5)) && 
me(ctx, dh(gs(ctx.getString(R.string.ct6), ctx.getString(R.string.k6)), flag), ctx.getString(R.string.t6));
}
```
file: strings.xml
```xml
 <string name="ct1">xwe</string>
    <string name="ct2">asd</string>
    <string name="ct3">uyt</string>
    <string name="ct4">42s</string>
    <string name="ct5">p0X</string>
    <string name="ct6">70 IJTR</string>
    <string name="k1">53P</string>
    <string name="k2">,7Q</string>
    <string name="k3">8=A</string>
    <string name="k4">yvF</string>
    <string name="k5">=tm</string>
    <string name="k6">dxa</string>
    <string name="m1">slauqe</string>
    <string name="t1">6e9a4d130a9b316e9201238844dd5124</string>
    <string name="t2">7c51a5e6ea3214af970a86df89793b19</string>
    <string name="t3">e5f20324ae520a11a86c7602e29ecbb8</string>
    <string name="t4">1885eca5a40bc32d5e1bca61fcd308a5</string>
    <string name="t5">da5062d64347e5e020c5419cebd149a2</string>
    <string name="t6">1c4d1410a4071880411f02ff46370e46b464ab2f87e8a487a09e13040d64e396</string>

```
</br>

**1. sum == 180**
```java
        char[] syms = new char[4];
        int[] idxs = {13, 21, 27, 32};
        Set<Character> chars = new HashSet<>();
        for (int i = 0; i < syms.length; i++) {
            syms[i] = flag.charAt(idxs[i]);
            chars.add(Character.valueOf(syms[i]));
        }
        int sum = 0;
        for (char c : syms) {
            sum += c;
        }
```
Take the fixed 4 characters in the flag to check. Simply the positions of the '-' </br>
**2. Use XOR to obtain the hash algorithm**
```java
    i = [1:6]
    gs(ctx.getString(R.string.cti), ctx.getString(R.string.ki))
    private static String gs(String a, String b) {
        String s = BuildConfig.FLAVOR;
        for (int i = 0; i < a.length(); i++) {
            s = s + Character.toString((char) (a.charAt(i) ^ b.charAt(i % b.length())));
        }
        return s;
    }
```
XOR each character of ct[i] with k[i] to generate the name of the hash algorithm. </br>
=> ps0-ps5: use MD5 to hash </br>
all flags: use SHA-256 to hash </br>
**3. Comparison using reflection**
```java
    private static boolean me(Context ctx, String s1, String s2) throws NoSuchMethodException, SecurityException {
        try {
            Class c = s1.getClass();
            Method m = c.getMethod(r(ctx.getString(R.string.m1)), Object.class);
            boolean res = ((Boolean) m.invoke(s1, s2)).booleanValue();
            return res;
        } catch (Exception e) {
            Log.e("MOBISEC", "Exception: " + Log.getStackTraceString(e));
            return false;
        }
    }
```
m1 = "slauqe" → reverse → "equals" </br>
The `me` function simply checks each part of the flag.
**4. Solve each part of the flag**
```java
//The partial hash values ​​of flags t1-t5 and the entire flag t6.
i:[1-6]
ctx.getString(R.string.t6)
<string name="t1">6e9a4d130a9b316e9201238844dd5124</string>
<string name="t2">7c51a5e6ea3214af970a86df89793b19</string>
<string name="t3">e5f20324ae520a11a86c7602e29ecbb8</string>
<string name="t4">1885eca5a40bc32d5e1bca61fcd308a5</string>
<string name="t5">da5062d64347e5e020c5419cebd149a2</string>
<string name="t6">1c4d1410a4071880411f02ff46370e46b464ab2f87e8a487a09e13040d64e396</string>
```
we just need to break few MD5 hashes and we can get our flag. For this we can use [crackstation](https://crackstation.net/).

MD5(ps0) = 6e9a4d130a9b316e9201238844dd5124
→ ps0 = "peppa"

MD5(ps1) = 7c51a5e6ea3214af970a86df89793b19
→ ps1 = "is"

MD5(ps2) = e5f20324ae520a11a86c7602e29ecbb8
→ ps2 = "BAAAM"

MD5(ps3) = 1885eca5a40bc32d5e1bca61fcd308a5
→ ps3 = "gnirts"

MD5(ps4) = da5062d64347e5e020c5419cebd149a2
→ ps4 = "123"

The result is that we just need to put all the parts of the flag together and check it.

**Complete flag:** MOBISEC{peppa-9876543-BAAAM-A1z9-3133337}

# **4.Solution of goingnative**
## **Description of the problem**
This task provides us with an Android application package (goingnative.apk). We need to disassemble and analyze the source code and find the hidden flags within.
## **Solution Idea**
Android applications use a Java FlagChecker class to check user-entered flags. However, the most crucial checking isn't done in Java but in native code via JNI (libnative-lib.so). Therefore, we need to analyze the Java code to understand the flag format and analyze the native code to find the correct flag value.
## **Description Solution**
### 1. We use jadx-gui to decompile the babyrev.apk package to obtain source code that is easier to analyze and understand.
### 2. From the source code. Let's analyze them.
### 3. Analyze the Java code, paying particular attention to the FlagChecker() class.
```java
class FlagChecker {
    private static native boolean helloFromTheOtherSide(String str, int i);

    FlagChecker() {
    }

    static {
        System.loadLibrary("native-lib");
    }

    public static boolean checkFlag(String str) {
        String[] strArrSplit = str.split("-");
        if (strArrSplit.length != 2 || !strArrSplit[0].startsWith("MOBISEC{") || !strArrSplit[1].endsWith("}")) {
            return false;
        }
        String strReplace = strArrSplit[0].replace("MOBISEC{", BuildConfig.FLAVOR);
        String strReplace2 = strArrSplit[1].replace("}", BuildConfig.FLAVOR);
        if (strReplace2.matches("^[0-9]*$") && strReplace2.length() == 6) {
            return helloFromTheOtherSide(strReplace, Integer.parseInt(strReplace2));
        }
        return false;
    }
}
```
Let's analyze the condition in the Java code above:
```
note :  BuildConfig.FLAVOR = ""
```
| Code                     |     Description                                         | 
|------------------------- |---------------------------------------------------------|
| String[] strArrSplit = str.split("-")| Divide the flag into segments separated by hyphens|
|strArrSplit.length != 2| The flag is divided into two parts|
|!strArrSplit[0].startsWith("MOBISEC{")| The first part begins with "MOBISEC{"|
|!strArrSplit[1].endsWith("}") | Part two ends with the symbol } |
|  String strReplace = strArrSplit[0].replace("MOBISEC{", BuildConfig.FLAVOR); | In the first part, remove "MOBISEC{"
|String strReplace2 = strArrSplit[1].replace("}", BuildConfig.FLAVOR); | In part two, remove "}" |
| strReplace2.matches("^[0-9]*$") && strReplace2.length() == 6| Part two consists only of numbers and is 6 characters long|


From the above analysis, we have the following flag format:
```
MOBISEC{<PART1>-<PART2>}
```
We couldn't find the exact flag from the Java code, but we found its format and and the code snippets that help us find the flag.
``` java 
   static {
        System.loadLibrary("native-lib");
    }
    helloFromTheOtherSide (strReplace, Integer.parseInt(strReplace2));
```
A function "helloFromTheOtherSide" was called with two arguments: the first part of the flag and the second part converted to an integer. And a piece of code to load the library, which includes the library's abbreviated name, is "native-lib".</br>
Note: Before an Android application can call and execute any code implemented in a native library, the application (Java code) must load that library into memory. API call: System.loadLibrary("native-lib");

### 4. Analyzing the "libnative-lib.so" library
The jadx-gui has extracted the necessary libraries. The resources/lib folder contains the original libraries for different CPU architectures. I've selected libnative-lib.so for x86_64. </br>
Since jadx doesn't support fle.so, I used Ghdra to decompile libnative-lib.so into C emulator. This makes it easier to read, understand, and analyze. </br>
#### 4.1 Analyzing the 'libnative-lib.so' library using **Ghidra**
``` c

ulong Java_com_mobisec_gonative_FlagChecker_helloFromTheOtherSide
                (long *param_1,undefined8 param_2,undefined8 param_3,int param_4)

{
  int iVar1;
  char *__s;
  size_t sVar2;
  ulong uVar3;
  long in_FS_OFFSET;
  char local_2e [5];
  undefined1 local_29;
  long local_28;
  
  local_28 = *(long *)(in_FS_OFFSET + 0x28);
  __s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  sVar2 = strlen(__s);
  if ((((sVar2 == 0xc) && (param_4 == 0x7a69)) && (*__s == 'n')) && (__s[0xb] == 'o')) {
    strncpy(local_2e,__s + 1,5);
    local_29 = 0;
    iVar1 = strncmp("ative",local_2e,5);
    if (((iVar1 == 0) && (__s[9] == '_')) &&
       ((__s[6] == '_' && ((__s[7] == 'i' && (__s[8] == 's')))))) {
      iVar1 = strcmp("so",__s + 10);
      uVar3 = CONCAT71((int7)((ulong)local_2e >> 8),iVar1 == 0);
      (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
      goto LAB_00100880;
    }
  }
  (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
  uVar3 = 0;
LAB_00100880:
  if (*(long *)(in_FS_OFFSET + 0x28) == local_28) {
    return uVar3 & 0xffffffff;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
From the code above, we can see that it is essentially: 
| Parameters in Ghidra | Real data type | Meaning |
|---------------------|-------------------|----------|
| `param_1` | `JNIEnv*` | Pointer to the JNI environment |
| `param_2` | `jclass` | Reference to the `FlagChecker` class |
| `param_3` | `jstring` | The left side of the flag |
| `param_4` | `jint` | The 6-digit number to the right of the flag |

Let's analyze it step by step:

*  Get the string from jstring: param_3
```c
__s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
```
This is the JNI call: equivalent to `GetStringUTFChars(env, param_3, 0)` converts a Java jstring object into a C-style null-terminated string encoded in modified UTF-8. </br>
Result: __s pointing to the C string of the `LEFT part` in the flag
* Calculate the length of the string
```c
sVar2 = strlen(__s); //sVar2 = length of the part1
```
* The first set of conditions for finding the correct parts of the flag
```c
if ((((sVar2 == 0xc) && (param_4 == 0x7a69)) && (*__s == 'n')) && (__s[0xb] == 'o'))
```

    1. sVar2 == 0xc => sVar == 12 => String length of part1 = 12 characters
    2. param_4 == 0x7a69 (hex) => param_4 == 31337 (dec) => part2 = 31337 but part2 needs 6 digits => part2 = 031337
    3. *__s == 'n' => The first character of part 1 is 'n' - __s[0] = 'n'
    4. __s[0xb] == 'o' => __s[11] == 'o' => The 12th character (index 11) of part 1 is 'o'

* Copy the first 5 characters of part 1 starting from position 1 into local_2e
```c
strncpy(local_2e,__s + 1,5);
local_29 = 0;
iVar1 = strncmp("ative",local_2e,5);
```

=> local_2e = __s[1:5] and iVar1: Compare the 5 characters just copied with "active". iVar1 == 0 means a perfect match.

* The second (internal) condition for finding the remaining characters of the flag
```c 
 if (((iVar1 == 0) && (__s[9] == '_')) &&
       ((__s[6] == '_' && ((__s[7] == 'i' && (__s[8] == 's'))))))
```

  1. iVar1 == 0 => means a perfect match => __s[1:5] = "ative"
  2. __s[9] = '_'
  3. __s[6] = '_'
  4. __s[7] = 'i'
  5. __s[8] = 's'
* Check the suffix with "so"
```c
iVar1 = strcmp("so",__s + 10);
```
Compare __s[10] and __s[11] with "so"
* Assign return value
```c 
  uVar3 = CONCAT71((int7)((ulong)local_2e >> 8),iVar1 == 0);
      (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
      goto LAB_00100880;
    }
  }
  (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
  uVar3 = 0;
LAB_00100880:
  if (*(long *)(in_FS_OFFSET + 0x28) == local_28) {
    return uVar3 & 0xffffffff; // Returns the true check flag result when uVar3 is not equal to 0.
  }
```
iVar1 == 0 → 1 if "so" is true, otherwise 0
CONCAT71(...) is just Ghidra's byte concatenation method
`The most important thing is that the value of uVar3 is:`
  * 1 if all conditions are true
  * 0 if false
=> Therefore, the correct flag will satisfy all the above conditions.

Finally, let's put all the parts we've found together, and that's the flag:
  * __s[0] = 'n'
  * __s[11] = 'o'
  * __s[1:5] = "ative"
  * __s[9] = '_'
  * __s[6] = '_'
  * __s[7] = 'i'
  * __s[8] = 's'
  * __s[10] = 's'
  * part2 = 031337

=> part1 = native_is_so ; part2 = 031337 

From the above analysis, we have the following flag format:
```
MOBISEC{<PART1>-<PART2>}
part1 = native_is_so ; part2 = 031337 
Complete flag: MOBISEC{native_is_so-031337}
```

# **5.Solution of blockchain**
## **Description of the problem**
This app asks for a KEY and a FLAG. We need to find a combination of KEY and FLAG such that the app shows "Valid Flag". Once we find a valid FLAG (no matter what the KEY is), submit it to the system to get points.
## **Solution Idea**
Code analysis reveals: The key space for encrypting the flag is small, AES-ECB has no IV, and it compares to hard-coded ciphertext. Therefore, we can brute-force to obtain the flag.

`Analyzing the application's workflow`
### 1. MainActivity
```java 
result = FlagChecker.checkFlag(key, flag);
```
The user enters the key and flag to check. A checkFlag function is then called to perform the check.
### 2.FlagChecker
I will add comments to the code so that we can easily understand and crack it to get the flag.
```java
class FlagChecker {
    static final /* synthetic */ boolean $assertionsDisabled = false;

    FlagChecker() {
    }

    public static boolean checkFlag(String keyStr, String flagStr) throws Exception {
        byte[] fullKey = keyStr.getBytes();
        byte[] digest = hash(fullKey);
        byte[] key = {digest[0], digest[digest.length / 2], digest[digest.length - 1]}; // 3 byte 
        byte[] currKey = hash(key);  // MD5(key3)
        byte[] currPt = flagStr.getBytes();
        for (int i = 0; i < 10; i++) { 
            byte[] newPt = encrypt(currPt, currKey);  // AES-ECB-PKCS5
            currPt = newPt;
            currKey = hash(currKey); // MD5 chaining
        }
        return toHex(currPt).equals
        ("0eef68c5ef95b67428c178f045e6fc8389b36a67bbbd800148f7c285f938a24e696ee2925e12ecf7c11f35a345a2a142639fe87ab2dd7530b29db87ca71ffda2af558131d7da615b6966fb0360d5823b79c26608772580bf14558e6b7500183ed7dfd41dbb5686ea92111667fd1eff9cec8dc29f0cfe01e092607da9f7c2602f5463a361ce5c83922cb6c3f5b872dcc088eb85df80503c92232bf03feed304d669ddd5ed1992a26674ecf2513ab25c20f95a5db49fdf6167fda3465a74e0418b2ea99eb2673d4c7e1ff7c4921c4e2d7b"); //The ciphertext string of the flag used for comparison.

    public static byte[] encrypt(byte[] in, byte[] key) throws Exception { // AES-ECB-PKCS5
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(1, aesKey);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(in);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        byte[] out = outputStream.toByteArray();
        return out;
    }

    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }

    public static String toHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 255);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```
From the code above, we can see that:
*  keyStr → MD5 → only 3 bytes are taken.
*  The actual key space is only 3 bytes = 2²⁴ ≈ 16 million.
*  The FLAG is encrypted with 10x AES-ECB.
*  The final result is compared with a fixed hex ciphertext.
### 3. Attack idea
Brute-force the entire 3-byte key. For each key: 
* Generate a 10-byte MD5 key sequence (similar to Java code)
* Decrypt using AES-ECB 10 times in reverse (Because AES is symmetric encryption, the encryption and decryption are exactly the same).
If:
* Padding is valid.
* The result is a valid ASCII → FLAG.
### 4. Python code used for the attack
```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CIPHERTEXT_HEX = (
    "0eef68c5ef95b67428c178f045e6fc8389b36a67bbbd800148f7c285f938a24e"
    "696ee2925e12ecf7c11f35a345a2a142639fe87ab2dd7530b29db87ca71ffda2a"
    "f558131d7da615b6966fb0360d5823b79c26608772580bf14558e6b7500183ed7"
    "dfd41dbb5686ea92111667fd1eff9cec8dc29f0cfe01e092607da9f7c2602f546"
    "3a361ce5c83922cb6c3f5b872dcc088eb85df80503c92232bf03feed304d669dd"
    "d5ed1992a26674ecf2513ab25c20f95a5db49fdf6167fda3465a74e0418b2ea99"
    "eb2673d4c7e1ff7c4921c4e2d7b"
)
CIPHERTEXT = bytes.fromhex(CIPHERTEXT_HEX)

def md5_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def aes_ecb_pkcs5_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES.block_size)

def decode_flag(key3: bytes) -> None:
    curr_pt = CIPHERTEXT

    # create a sequence of keys: keys[0] = MD5(key3), keys[i] = MD5(keys[i-1]) (tổng 10 key)
    keys = [md5_hash(key3)]
    for i in range(1, 10):
        keys.append(md5_hash(keys[i - 1]))

    # Decode 10 times in reverse order: keys[9], keys[8], ..., keys[0]
    try:
        for i in range(10):
            curr_pt = aes_ecb_pkcs5_decrypt(curr_pt, keys[9 - i])
    except ValueError:
        return

    # new String(currPt) and regex ASCII
    if all(b < 128 for b in curr_pt):
        try:
            print(curr_pt.decode("ascii"))
        except UnicodeDecodeError:
            pass

def main():
    for i in range(-128, 128):
        for j in range(-128, 128):
            for k in range(-128, 128):
                # Python bytes need 0..255 => & 0xff
                key3 = bytes([k & 0xFF, j & 0xFF, i & 0xFF])
                decode_flag(key3)

if __name__ == "__main__":
    main()
```
**Complete flag:** MOBISEC{blockchain_failed_to_deliver_once_again}

# **6.Solution of loadme**
## **Description of the problem**
The application prompts the user to enter a FLAG, then displays a true or false result. However, the flag checking logic is not directly embedded in the main APK, but is hidden through multiple layers. Therefore, reverse engineering, analysis, and layer-by-layer extraction are necessary to obtain the flag.
## **Solution Idea**
Analyze the entire application code – decode – dynamically load to find the logic for checking the final flag, and from there deduce the valid flag.</br>
The problem is divided into three main layers:
* Main APK – Loader
* Stage 1 APK – Subsequent Loader
* Stage 2 APK – Contains logic for checking the actual flag

`Analyzing the application's workflow`
### **1. Loader**
* `Mainactivity.java`

```java
DoStuff doStuff = new DoStuff();
result = doStuff.start(MainActivity.this, flag);
Log.d("MOBISEC", "Flag result: " + result);
```
A doStuff class is called to check the flag.
* `DoStuff`
```java
    private String gu() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException { //get link
        String url = ds("MAi9CEe4K9a+JzgsNqdYYh13dk7SQQ/yo5BN5HF39nYtgnOBmO4EV9Y2sQDthTG9");
        return url;
    }
    private String dc(String url) throws IOException { //dowload file from url
        try {
            URL downloaded_url = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) downloaded_url.openConnection();
            urlConnection.connect();
            File file = new File(this.context.getCodeCacheDir(), gf());
            FileOutputStream fileOutput = new FileOutputStream(file);
            InputStream inputStream = urlConnection.getInputStream();
            byte[] buffer = new byte[1024];
            while (true) {
                int bufferLength = inputStream.read(buffer);
                if (bufferLength <= 0) {
                    fileOutput.close();
                    return file.getAbsolutePath();
                }
                fileOutput.write(buffer, 0, bufferLength);
            }
        } catch (Exception e) {
            return null;
        }
    }
    //decord enc-url to get original url
    private String ds(String enc) throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            String[] parts = this.context.getPackageName().split(Pattern.quote("."));
            String key = parts[1] + parts[0] + "key!!!";
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(2, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decode(enc.getBytes(), 0));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    } 
    // function start
    public boolean start(Context ctx, String flag) throws IOException {
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        setContext(ctx);
        setUserInput(flag);
        String path = dc(gu()); // download file stage1.apk
        da(path); // xor stage1.apk vs key = stage1_dec.apk
        return lc(path); 
    }
    //da function: xor and write new file apk
    private void da(String path) throws IOException {
        byte[] xorKey = this.context.getPackageName().getBytes();
        File file = new File(path);
        int size = (int) file.length();
        byte[] bytes = new byte[size];
        byte[] decbytes = new byte[size];
        try {
            BufferedInputStream buf = new BufferedInputStream(new FileInputStream(file));
            buf.read(bytes, 0, bytes.length);
            buf.close();
            for (int i = 0; i < size; i++) {
                decbytes[i] = (byte) (bytes[i] ^ xorKey[i % xorKey.length]);
            }
            File outFile = new File(path);
            FileOutputStream out = new FileOutputStream(outFile, false);
            out.write(decbytes);
            out.flush();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

``` 
In the DoStuff class, the application: 
* Decrypt URL strings using AES/CBC/PKCS5Padding
* Keys are dynamically generated from the package name: `mobiseccomkey!!!`
* IV fixation: `deadbeefdeadbeefdeadbeefdeadbeef` : Convert negative bytes in Java to hex </br>
=> After decoding, the real URL is: https://challs.reyammer.io/loadme/stage1.apk </br>
The downloaded file is not a valid APK, but has been XORed with the key:
* key: com.mobisec.dexclassloader
* After performing the XOR operation, we obtain stage1_dec.apk. 

`Note`: If you don't want to run the APK in Java, here's a short Python code snippet.
```python
key = b"com.mobisec.dexclassloader"
with open("sample_data/stage1.apk", "rb") as f:
    data = f.read()
dec = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
with open("stage1_dec.apk", "wb") as f:
    f.write(dec)
print("stage1_dec.apk ready")
```
### **2.Stage 1 – Decode assets and load Stage 2**
Analyzing the stage1_dec.apk file:
* `LoadImage.java`
```java
    public static boolean load(Context ctx, String flag) throws IOException {
        byte[] xorKey = "weneedtogodeeper".getBytes();
        setContext(ctx);
        AssetManager assetManager = ctx.getAssets();
        try {
            InputStream in = assetManager.open(getAssetsName());
            File outFile = new File(ctx.getCodeCacheDir().getAbsolutePath(), getCodeName());
            OutputStream out = new FileOutputStream(outFile);
            byte[] buffer = new byte[1024];
            while (true) {
                int read = in.read(buffer);
                if (read != -1) {
                    out.write(buffer, 0, read);
                } else {
                    in.close();
                    out.close();
                    decryptApk(outFile.getAbsolutePath(), xorKey);
                    return loadClass(ctx, outFile.getAbsolutePath(), flag);
                }
            }
        } catch (Exception e) {
            return false;
        }
    }
```
Analyzing the code in LoadImage, we see:
* There are few encrypted strings we have to get around it but since keys and methods to decrypt are in apk itself it's not a big problem.
* This stage1_dec.apk will load logo.png from loadme.apk, decrypt it (just xor), load that apk and call checkFlag from it.
* We have xorKey = "weneedtogodeeper"

=> `After the XOR operation, a valid stage2.apk is obtained.`

`Note`: Python code to get file stage2.apk
```python
key = b"weneedtogodeeper"
with open("sample_data/logo.png", "rb") as f:
    data = f.read()
dec = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
with open("stage2.apk", "wb") as f:
    f.write(dec)
print("stage2.apk ready")
```
### **3.Stage 2 – Check the flag**
* Check class:
```java
package com.mobisec.stage2;
/* loaded from: classes.dex */
public class Check {
    public static boolean check(String flag) {
        return flag.equals("MOBISEC{dynamic_code_loading_can_make_everything_tricky_eh?}");
    }
}
```
**Complete flag:** MOBISEC{dynamic_code_loading_can_make_everything_tricky_eh?}

# **7.Solution of upos**
## **Description of the problem**
The Android upos application prompts the user to enter a string of “flag”. The application checks the flag and returns true if it is correct. During the checking process, the application also has “anti-debug/anti-frida/anti-tamper/anti-root” mechanisms through the variables: `MainActivity.g1, g2, g3, g4`
## **Solution Idea**
Use jadx-gui to analyze the code logic and flag check conditions to recover a valid flag.
## **Solution details**
In jadx-gui, if you use code mode, it's very difficult to detect the conditions because the assembly code is hard to read. But when you use simple mode, you can see almost all the conditions and the flag condition strings.

`mode simple`
```java
/* loaded from: classes2.dex */
public class FC {
    public static Context ctx;
    public static long[][] m;

    public FC() {
    }

    static {
        ctx = null;
        m = (long[][]) Array.newInstance(long.class, new int[]{256, 256});
    }

    /* JADX DEBUG: Don't trust debug lines info. Repeating lines: [336=11, 340=11, 344=11, 348=10, 352=10, 195=7, 232=7] */
    public static boolean checkFlag(Context ctx2, String fl) {
        Activity.initActivity((MainActivity) ctx2);
        ctx = ctx2;
        boolean[] fs = new boolean[200];
        Streamer s = new Streamer();
        lm(m);     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        if (fl.length() == 69) goto L8;
        return false;
    L8:
        int idx = 0 + 1;
        fs[0] = fl.startsWith("MOBISEC{");     // Catch: Exception -> L314 GeneralSecurityException -> L316 RejectedExecutionException -> L318 CertificateEncodingException -> L320 BatchUpdateException -> L322
        String core = fl.substring(8);     // Catch: Exception -> L314 GeneralSecurityException -> L316 RejectedExecutionException -> L318 CertificateEncodingException -> L320 BatchUpdateException -> L322
        int idx2 = idx + 1;
        fs[idx] = core.endsWith("}");     // Catch: Exception -> L304 GeneralSecurityException -> L306 RejectedExecutionException -> L308 CertificateEncodingException -> L310 BatchUpdateException -> L312
        boolean f = true;
        s.step();     // Catch: NullPointerException -> L154 IllformedLocaleException -> L158 Exception -> L304 GeneralSecurityException -> L306 RejectedExecutionException -> L308 CertificateEncodingException -> L310 BatchUpdateException -> L312
        if (MainActivity.g2 == false) goto L16;
        return false;
    L16:
        s.step();     // Catch: NullPointerException -> L154 IllformedLocaleException -> L158 Exception -> L304 GeneralSecurityException -> L306 RejectedExecutionException -> L308 CertificateEncodingException -> L310 BatchUpdateException -> L312
        s.step();     // Catch: NullPointerException -> L154 IllformedLocaleException -> L158 Exception -> L304 GeneralSecurityException -> L306 RejectedExecutionException -> L308 CertificateEncodingException -> L310 BatchUpdateException -> L312
        int idx3 = idx2 + 1;
        fs[idx2] = core.startsWith("this_is_");     // Catch: Exception -> L140 GeneralSecurityException -> L142 RejectedExecutionException -> L144 CertificateEncodingException -> L146 BatchUpdateException -> L148 NullPointerException -> L150 IllformedLocaleException -> L152
        int idx4 = idx3 + 1;
        fs[idx3] = core.endsWith("upos");     // Catch: NullPointerException -> L136 IllformedLocaleException -> L138 RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        idx2 = idx4 + 1;
        if (core.charAt(10) != 'c') goto L25;
    L28:
        boolean r9 = true;
    L29:
        fs[idx4] = r9;     // Catch: IllegalFormatCodePointException -> L132 NullPointerException -> L154 IllformedLocaleException -> L158 Exception -> L304 GeneralSecurityException -> L306 RejectedExecutionException -> L308 CertificateEncodingException -> L310 BatchUpdateException -> L312
        idx4 = idx2 + 1;
        if ((core.charAt(3) + core.charAt(7)) != 114) goto L34;
        boolean r92 = true;
    L35:
        fs[idx2] = r92;     // Catch: IllegalFormatCodePointException -> L130 NullPointerException -> L136 IllformedLocaleException -> L138 RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        s.step();     // Catch: IllegalFormatCodePointException -> L130 NullPointerException -> L136 IllformedLocaleException -> L138 RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        int idx5 = idx4 + 1;
        fs[idx4] = core.contains("really_");     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        boolean found = false;
        String[] lines = ec(dec(ctx2.getString(R.string.s1)) + " " + dec(ctx2.getString(R.string.s2))).split("\n");     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        int r12 = lines.length;     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        int r15 = 0;
    L38:
        if (r15 >= r12) goto L43;
        String line = lines[r15];     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        String maps = dec(ctx2.getString(R.string.s3)) + " " + dec(ctx2.getString(R.string.s2)) + "/" + line + "/maps";     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        String out = ec(maps);     // Catch: Exception -> L114 GeneralSecurityException -> L116 RejectedExecutionException -> L118 CertificateEncodingException -> L120 BatchUpdateException -> L122 NullPointerException -> L124 IllformedLocaleException -> L126 IllegalFormatCodePointException -> L128
        if (out.contains(dec(ctx2.getString(R.string.s4))) == true) goto L41;
        r15 = r15 + 1;
        goto L38
    L41:
        found = true;
        goto L43
    L43:
        int idx6 = idx5 + 1;
        fs[idx5] = found;     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 IllegalFormatCodePointException -> L112 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        if (fs[idx6 - 1] == true) goto L107;
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 IllegalFormatCodePointException -> L112 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        int idx7 = idx6 + 1;
        fs[idx6] = core.substring(14).endsWith("_evil");     // Catch: Exception -> L90 GeneralSecurityException -> L92 RejectedExecutionException -> L94 CertificateEncodingException -> L96 BatchUpdateException -> L98 NullPointerException -> L100 IllformedLocaleException -> L102 IllegalFormatCodePointException -> L104
        int idx8 = idx7 + 1;
        fs[idx7] = core.substring(9, 13).endsWith("bam");     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 IllegalFormatCodePointException -> L112 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 IllegalFormatCodePointException -> L112 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        if (MainActivity.g4 == false) goto L54;
        return false;
    L54:
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 IllegalFormatCodePointException -> L112 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        List<ApplicationInfo> packages = ctx2.getPackageManager().getInstalledApplications(128);     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        boolean found2 = false;
        Iterator<ApplicationInfo> r8 = packages.iterator();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
    L57:
        if (r8.hasNext() == false) goto L62;
        ApplicationInfo info = r8.next();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        if (info.packageName.equals(dec(ctx2.getString(R.string.s5))) == false) goto L57;
        found2 = true;
    L62:
        int idx9 = idx8 + 1;
        fs[idx8] = found2;     // Catch: Exception -> L76 GeneralSecurityException -> L78 RejectedExecutionException -> L80 CertificateEncodingException -> L82 BatchUpdateException -> L84 NullPointerException -> L86 IllformedLocaleException -> L88
        s.step();     // Catch: Exception -> L76 GeneralSecurityException -> L78 RejectedExecutionException -> L80 CertificateEncodingException -> L82 BatchUpdateException -> L84 NullPointerException -> L86 IllformedLocaleException -> L88
        int idx10 = idx9 + 1;
        fs[idx9] = core.substring(4, 10).toLowerCase().equals("incred");     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        if (MainActivity.g1 == false) goto L69;
        return false;
    L69:
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        if (s.step() > 0) goto L75;
        if (MainActivity.g1 == false) goto L75;
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        s.step();     // Catch: NullPointerException -> L108 IllformedLocaleException -> L110 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
    L177:
        if (f == false) goto L180;
        return false;
    L180:
        int idx11 = idx10 + 1;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        if (core.toLowerCase().substring(11, 14).charAt(1) != '4') goto L183;
        boolean r3 = true;
    L184:
        fs[idx10] = r3;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        int idx12 = idx11 + 1;
        fs[idx11] = core.substring(22).toUpperCase().startsWith("mayb");     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        PackageManager pm = ctx2.getPackageManager();     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        String packageName = ctx2.getPackageName();     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        PackageInfo packageInfo = null;
        packageInfo = pm.getPackageInfo(packageName, 64);     // Catch: PackageManager.NameNotFoundException -> L190 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
    L193:
        Signature[] signatures = packageInfo.signatures;     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        byte[] cert2 = signatures[0].toByteArray();     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        InputStream input = new ByteArrayInputStream(cert2);     // Catch: Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
        CertificateFactory cf = null;
        cf = CertificateFactory.getInstance("X509");     // Catch: CertificateException -> L197 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
    L200:
        X509Certificate c = null;
        c = (X509Certificate) cf.generateCertificate(input);     // Catch: CertificateException -> L203 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 CertificateEncodingException -> L296 BatchUpdateException -> L298
    L363:
        MessageDigest md = MessageDigest.getInstance("SHA1");     // Catch: CertificateEncodingException -> L221 NoSuchAlgorithmException -> L224 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 BatchUpdateException -> L298
    L365:
    L367:
        byte[] publicKey = md.digest(c.getEncoded());     // Catch: CertificateEncodingException -> L213 NoSuchAlgorithmException -> L215 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 BatchUpdateException -> L298
        String hexString = th(publicKey);     // Catch: CertificateEncodingException -> L213 NoSuchAlgorithmException -> L215 Exception -> L290 GeneralSecurityException -> L292 RejectedExecutionException -> L294 BatchUpdateException -> L298
        String hexString2 = hexString;
    L228:
        int idx13 = idx12 + 1;
        fs[idx12] = hexString2.equals(ctx2.getString(R.string.s6));     // Catch: Exception -> L280 GeneralSecurityException -> L282 RejectedExecutionException -> L284 CertificateEncodingException -> L286 BatchUpdateException -> L288
        if (fs[idx13 - 1] == false) goto L279;
        if (fs[0] == true) goto L234;
        return false;
    L234:
        if (fs[1] == false) goto L407;
        int i = 0;
        int idx14 = 100;
    L238:
        if (i >= 30) goto L263;
        fs[idx14] = true;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        String curr = Character.toString(core.charAt(i * 2)) + Character.toString(core.charAt((i * 2) + 1));     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        if (ip(i) == false) goto L245;
        int j = 0;
    L243:
        if (j >= i) goto L245;
        s.step();     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        j = j + 1;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
    L245:
        int j2 = s.g2();     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        int mX = j2 & 255;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        int mY = (s.g2() & MotionEventCompat.ACTION_POINTER_INDEX_MASK) >> 8;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        if (sq(r(curr)) == m[mX][mY]) goto L261;
        int idx15 = idx14 + 1;
        fs[idx14] = false;     // Catch: Exception -> L251 GeneralSecurityException -> L253 RejectedExecutionException -> L255 CertificateEncodingException -> L257 BatchUpdateException -> L259
        idx14 = idx15;
    L262:
        i = i + 1;
        goto L238
    L258:
        boolean r32 = true;
    L342:
        MainActivity.g1 = r32;
        return false;
    L260:
        boolean r33 = true;
    L345:
        MainActivity.g2 = r33;
        return false;
    L256:
        boolean r34 = true;
    L339:
        MainActivity.g3 = r34;
        return false;
    L412:
        return false;
    L261:
        idx14 = idx14 + 1;
        goto L262
    L263:
        int i2 = idx14 - 30;
    L264:
        if (i2 >= idx14) goto L271;
        if (fs[i2] == false) goto L267;
        i2 = i2 + 1;     // Catch: RejectedExecutionException -> L324 CertificateEncodingException -> L326 BatchUpdateException -> L328 Exception -> L330 GeneralSecurityException -> L334
        goto L264
    L267:
        return false;
    L271:
        if (h(fl).equals("4193d9b72a5c4805e9a5cc739f8a8fc23b2890e13b83bb887d96f86c30654a12") == true) goto L274;
    ...
```
Overview of the check logic:
* flag.length() == 69
* The flag must start with "MOBISEC{" and end with "}"
* Thus, the overall flag has the form: MOBISEC{<payload>} and the total length is exactly 69.

### **1.Check based on lotto.dat + LFSR (Streamer)**
Matrix m[256][256] from assets lotto.dat. The lm(m) function reads the asset/lotto.dat file: This is the "confidential data sheet" used for comparison.
* Streamer Pseudo-Random Number Generator:
    * Default seed: "01101000010"
    * tap = 8
    * step() shifts and generates new bits
    * g2() calls step() 16 times to generate a 16-bit number
    * In the check loop, the app takes two indices: idx1 = g2() & 0xFF, idx2 = (g2() & 0xFF00) >> 8
    * then accesses: target = m[idx1][idx2]
* Payload inside {}:
    * In the for i in 0-29 loop (30 times), each time we get 2 characters: pair = payload[2*i : 2*i+2]
    * pair2 = r(pair) and r() is a Caesar shift: A–Z letters / a–z shift +7 (mod 26 loop)
    * sq(pair2) returns n^2
    * Core condition: For each i, we must have:sq(r(pair)) == m[idx1][idx2]
### **2.Attack method**
* Bruteforce the initial offset in a small range (0-512)
* For each offset, construct the payload as above → construct flag = MOBISEC{payload}
* Check the final condition in the code: SHA-256(flag) must be equal to a constant:
`4193d9b72a5c4805e9a5cc739f8a8fc23b2890e13b83bb887d96f86c30654a12`

`Python script`:
```python
import math, hashlib

EXPECTED_SHA256 = "4193d9b72a5c4805e9a5cc739f8a8fc23b2890e13b83bb887d96f86c30654a12"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def ip(x: int) -> bool:
    for i in range(2, x):
        if x % i == 0:
            return False
    return True

def inv_rot_char(ch: str) -> str:
    o = ord(ch)
    if 97 <= o <= 122:  # a-z
        return chr(((o - 97 - 7) % 26) + 97)
    if 65 <= o <= 90:   # A-Z
        return chr(((o - 65 - 7) % 26) + 65)
    return ch

def sqrt_u16_square(x: int):
    r = int(math.isqrt(x))
    if r * r != x:
        return None
    if not (0 <= r <= 0xFFFF):
        return None
    return r

class Streamer:
    def __init__(self, seed="01101000010", tap=8):
        self.lfsr = [c == "1" for c in seed]
        self.tap = (len(seed) - 1) - tap

    def step(self) -> int:
        new_bit = self.lfsr[self.tap] ^ self.lfsr[0]
        for i in range(len(self.lfsr) - 1):
            self.lfsr[i] = self.lfsr[i + 1]
        self.lfsr[-1] = new_bit
        return 1 if new_bit else 0

    def g2(self) -> int:
        val = 0
        for i in range(16):
            val |= (self.step() << i)
        return val

def load_matrix(path="/content/lotto.dat"):
    m = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 256:
                raise ValueError(f"Bad row: expected 256 cols, got {len(parts)}")
            m.append([int(x) for x in parts])
    if len(m) != 256:
        raise ValueError(f"Bad file: expected 256 rows, got {len(m)}")
    return m

def compute_payload(m, offset_steps: int):
    s = Streamer()
    for _ in range(offset_steps):
        s.step()

    out = []
    for i in range(30):
        if ip(i):
            for _ in range(i):
                s.step()

        idx1 = s.g2() & 0xFF
        idx2 = (s.g2() & 0xFF00) >> 8

        v = m[idx1][idx2]
        n = sqrt_u16_square(v)
        if n is None:
            return None

        obf0 = chr(n & 0xFF)
        obf1 = chr((n >> 8) & 0xFF)
        out.append(inv_rot_char(obf0) + inv_rot_char(obf1))

    return "".join(out)

def find_flag(path="/content/lotto.dat", max_offset=256):
    m = load_matrix(path)
    for off in range(max_offset + 1):
        payload = compute_payload(m, off)
        if payload is None:
            continue
        flag = f"MOBISEC{{{payload}}}"
        if sha256_hex(flag) == EXPECTED_SHA256:
            return off, flag
    return None

res = find_flag("lotto.dat", max_offset=512)
print(res)
```
**Complete flag:** MOBISEC{Isnt_this_a_truly_evil_undebuggable_piece_of_sh^W_software??}
