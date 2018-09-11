UMTools

Special-purpose tools for Ultra Messaging

FILES:

1. ummon.c		-> lbmmon.c clone with output written in SVF format.
2. umpub.c		-> UMP publisher for capacity testing.
3. umsub.c		-> UMP receiver for capacity testing.
4. LBMMON_JSON(java)	-> Combines lbmmon.java with umedmon.c and tnwgdmon.c parsers (compiled into a JNI function) to parse statistics
			   from UM applications and Daemons; with output formatted as JSON by default.
			-> Also includes lbmmond_java which uses the LBMContext.send() API to send requests for statistics to the umestored and tnwgd daemons.
5. TRSNIFFER(c)		-> Utility for parsing Topic Resolution streams 


