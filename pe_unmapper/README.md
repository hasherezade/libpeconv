# pe_unmapper
Small tool to convert a PE from a virtual format into a raw format<br/>
(useful in recovering executables dumped from the memory).<br/>

Usage:<br>
<pre>
pe_unmapper.exe [input_file] [load base: in hex] [*output_file]
* - optional
</pre>
Example:</br>
<pre>
pe_unmapper.exe _02660000.mem 02660000 payload.dll
</pre>
<br/>

