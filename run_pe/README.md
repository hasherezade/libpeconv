# Demo: RunPE

This is a demo project using _libpeconv_.<br/>
RunPE (aka Process Hollowing) is a well known technique allowing to injecting a new PE into a remote processes, imprersonating this process.

![](https://blog.malwarebytes.com/wp-content/uploads/2018/08/hollowing1-1_.png)

The given implementation works for PE 32bit as well as 64bit.<br/>

Supported injections:
-
If the loader was built as 32 bit:
```
32 bit payload -> 32 bit target
```
If the loader was built as 64 bit:
```
64 bit payload -> 64 bit target
32 bit payload -> 32 bit target
```

How to use the app:
-
Supply 2 commandline arguments:

```
[payload_path] [target_path]
```

Payload is the PE to be executed impersonating the Target.
