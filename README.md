# capmerge2

![Alt text](http://fmad.io/analytics/logo_capmerge.png "fmadio flow analyzer logo")

capmerge2 is a high performance PCAP merging utiltity based on mmap, that merges the input PCAP`s in time order outputing a nanosecond PCAP. What makes this different from wireshark mergecap is its performance. You can merge 200GB`s worth of pcap`s in 10 minutes or less, bound by the raw DiskIO bandwidth. 

###Options

Command line options

```
-o <filename>                              | location of output pcap file 
```

###Options
```
$ ./capmerge2  -o output.pcap  input_20160114_0000.pcap input_20160114_0100.pcap input_20160114_0200.pcap input_20160114_0300.pcap 
calibrating...
0 : 00000000d09dae93           3.5000 cycles/nsec
Cycles/Sec 3499994771.0000 Std:       0cycle std(  0.00000000)
	[0.0000 %] 0.000GB 0.358543Gbps Elapsed:0.000000 Min ETA:88 Min
	[0.0024 %] 0.579GB 4.631682Gbps Elapsed:0.016667 Min ETA: 7 Min
	[0.0037 %] 0.873GB 3.489794Gbps Elapsed:0.033367 Min ETA: 9 Min
	[0.0048 %] 1.133GB 3.014061Gbps Elapsed:0.050100 Min ETA:10 Min
	[0.0059 %] 1.390GB 2.776663Gbps Elapsed:0.066767 Min ETA:11 Min
	[0.0070 %] 1.658GB 2.649252Gbps Elapsed:0.083434 Min ETA:12 Min
	[0.0080 %] 1.902GB 2.533846Gbps Elapsed:0.100100 Min ETA:12 Min
	[0.0092 %] 2.171GB 2.477583Gbps Elapsed:0.116834 Min ETA:13 Min
	[0.0102 %] 2.417GB 2.412619Gbps Elapsed:0.133567 Min ETA:13 Min
	[0.0114 %] 2.700GB 2.395473Gbps Elapsed:0.150300 Min ETA:13 Min
	[0.0124 %] 2.937GB 2.345712Gbps Elapsed:0.166967 Min ETA:13 Min
	[0.0135 %] 3.203GB 2.324527Gbps Elapsed:0.183700 Min ETA:13 Min
	[0.0146 %] 3.456GB 2.299625Gbps Elapsed:0.200367 Min ETA:14 Min
	[0.0156 %] 3.710GB 2.278671Gbps Elapsed:0.217101 Min ETA:14 Min
	[0.0168 %] 3.975GB 2.267476Gbps Elapsed:0.233767 Min ETA:14 Min
	[0.0178 %] 4.225GB 2.248609Gbps Elapsed:0.250500 Min ETA:14 Min
	[0.0189 %] 4.486GB 2.238679Gbps Elapsed:0.267167 Min ETA:14 Min
```

