# pe_unmapper

Small tool to convert beteween the PE alignments (raw and virtual).

Allows for easy PE unmapping: useful in recovering executables dumped from the memory.

Usage:

```
Args:

Required: 
/in	: Input file name

Optional: 
/base	: Base address where the image was loaded: in hex
/out	: Output file name
/mode	: Choose the conversion mode:
	 U: UNMAP (Virtual to Raw) [DEFAULT]
	 M: MAP (Raw to Virtual)
	 R: REALIGN (Virtual to Raw, where: Raw == Virtual)
```
Example:

```
pe_unmapper.exe /in _02660000.mem /base 02660000 /out payload.dll
```
Compiled version available:
+ [here](https://drive.google.com/uc?export=download&id=1hJMHFYXxcW1w14KFhlVZ3PbHuOc6pbN4)
+ via [AppVeyor build server](https://ci.appveyor.com/project/hasherezade/libpeconv) (click on the build and choose the "Artifacts" tab)

