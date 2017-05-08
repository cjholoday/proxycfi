
a.out:     file format elf64-x86-64


Disassembly of section .interp:

0000000000400200 <.interp>:
  400200:	2f                   	(bad)  
  400201:	6c                   	insb   (%dx),%es:(%rdi)
  400202:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
  400209:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
  40020e:	78 2d                	js     40023d <.CDI_sled_id_5_len+0x40021a>
  400210:	78 38                	js     40024a <.CDI_sled_id_5_len+0x400227>
  400212:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
  400218:	6f                   	outsl  %ds:(%rsi),(%dx)
  400219:	2e 32 00             	xor    %cs:(%rax),%al

Disassembly of section .note.ABI-tag:

000000000040021c <.note.ABI-tag>:
  40021c:	04 00                	add    $0x0,%al
  40021e:	00 00                	add    %al,(%rax)
  400220:	10 00                	adc    %al,(%rax)
  400222:	00 00                	add    %al,(%rax)
  400224:	01 00                	add    %eax,(%rax)
  400226:	00 00                	add    %al,(%rax)
  400228:	47                   	rex.RXB
  400229:	4e 55                	rex.WRX push %rbp
  40022b:	00 00                	add    %al,(%rax)
  40022d:	00 00                	add    %al,(%rax)
  40022f:	00 02                	add    %al,(%rdx)
  400231:	00 00                	add    %al,(%rax)
  400233:	00 06                	add    %al,(%rsi)
  400235:	00 00                	add    %al,(%rax)
  400237:	00 20                	add    %ah,(%rax)
  400239:	00 00                	add    %al,(%rax)
	...

Disassembly of section .hash:

0000000000400240 <.hash>:
  400240:	01 00                	add    %eax,(%rax)
  400242:	00 00                	add    %al,(%rax)
  400244:	03 00                	add    (%rax),%eax
  400246:	00 00                	add    %al,(%rax)
  400248:	02 00                	add    (%rax),%al
	...
  400252:	00 00                	add    %al,(%rax)
  400254:	01 00                	add    %eax,(%rax)
	...

Disassembly of section .dynsym:

0000000000400258 <.dynsym>:
	...
  400270:	0b 00                	or     (%rax),%eax
  400272:	00 00                	add    %al,(%rax)
  400274:	12 00                	adc    (%rax),%al
	...
  400286:	00 00                	add    %al,(%rax)
  400288:	1d 00 00 00 20       	sbb    $0x20000000,%eax
	...

Disassembly of section .dynstr:

00000000004002a0 <.dynstr>:
  4002a0:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
  4002a4:	63 2e                	movslq (%rsi),%ebp
  4002a6:	73 6f                	jae    400317 <.CDI_sled_id_5_len+0x4002f4>
  4002a8:	2e 36 00 5f 5f       	cs add %bl,%ss:0x5f(%rdi)
  4002ad:	6c                   	insb   (%dx),%es:(%rdi)
  4002ae:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
  4002b5:	72 74                	jb     40032b <.CDI_sled_id_5_len+0x400308>
  4002b7:	5f                   	pop    %rdi
  4002b8:	6d                   	insl   (%dx),%es:(%rdi)
  4002b9:	61                   	(bad)  
  4002ba:	69 6e 00 5f 5f 67 6d 	imul   $0x6d675f5f,0x0(%rsi),%ebp
  4002c1:	6f                   	outsl  %ds:(%rsi),(%dx)
  4002c2:	6e                   	outsb  %ds:(%rsi),(%dx)
  4002c3:	5f                   	pop    %rdi
  4002c4:	73 74                	jae    40033a <_init+0xa>
  4002c6:	61                   	(bad)  
  4002c7:	72 74                	jb     40033d <_init+0xd>
  4002c9:	5f                   	pop    %rdi
  4002ca:	5f                   	pop    %rdi
  4002cb:	00 47 4c             	add    %al,0x4c(%rdi)
  4002ce:	49                   	rex.WB
  4002cf:	42                   	rex.X
  4002d0:	43 5f                	rex.XB pop %r15
  4002d2:	32 2e                	xor    (%rsi),%ch
  4002d4:	32 2e                	xor    (%rsi),%ch
  4002d6:	35                   	.byte 0x35
	...

Disassembly of section .gnu.version:

00000000004002d8 <.gnu.version>:
  4002d8:	00 00                	add    %al,(%rax)
  4002da:	02 00                	add    (%rax),%al
	...

Disassembly of section .gnu.version_r:

00000000004002e0 <.gnu.version_r>:
  4002e0:	01 00                	add    %eax,(%rax)
  4002e2:	01 00                	add    %eax,(%rax)
  4002e4:	01 00                	add    %eax,(%rax)
  4002e6:	00 00                	add    %al,(%rax)
  4002e8:	10 00                	adc    %al,(%rax)
  4002ea:	00 00                	add    %al,(%rax)
  4002ec:	00 00                	add    %al,(%rax)
  4002ee:	00 00                	add    %al,(%rax)
  4002f0:	75 1a                	jne    40030c <.CDI_sled_id_5_len+0x4002e9>
  4002f2:	69 09 00 00 02 00    	imul   $0x20000,(%rcx),%ecx
  4002f8:	2c 00                	sub    $0x0,%al
  4002fa:	00 00                	add    %al,(%rax)
  4002fc:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

0000000000400300 <.rela.dyn>:
  400300:	a8 1c                	test   $0x1c,%al
  400302:	60                   	(bad)  
  400303:	00 00                	add    %al,(%rax)
  400305:	00 00                	add    %al,(%rax)
  400307:	00 06                	add    %al,(%rsi)
  400309:	00 00                	add    %al,(%rax)
  40030b:	00 02                	add    %al,(%rdx)
	...

Disassembly of section .rela.plt:

0000000000400318 <.rela.plt>:
  400318:	c8 1c 60 00          	enterq $0x601c,$0x0
  40031c:	00 00                	add    %al,(%rax)
  40031e:	00 00                	add    %al,(%rax)
  400320:	07                   	(bad)  
  400321:	00 00                	add    %al,(%rax)
  400323:	00 01                	add    %al,(%rcx)
	...

Disassembly of section .init:

0000000000400330 <_init>:
  400330:	48 83 ec 08          	sub    $0x8,%rsp
  400334:	48 8b 05 6d 19 20 00 	mov    0x20196d(%rip),%rax        # 601ca8 <_DYNAMIC+0x1d0>
  40033b:	48 85 c0             	test   %rax,%rax
  40033e:	74 05                	je     400345 <_init+0x15>
  400340:	e8 2b 00 00 00       	callq  400370 <__libc_start_main@plt+0x10>
  400345:	48 83 c4 08          	add    $0x8,%rsp
  400349:	c3                   	retq   

Disassembly of section .plt:

0000000000400350 <__libc_start_main@plt-0x10>:
  400350:	ff 35 62 19 20 00    	pushq  0x201962(%rip)        # 601cb8 <_GLOBAL_OFFSET_TABLE_+0x8>
  400356:	ff 25 64 19 20 00    	jmpq   *0x201964(%rip)        # 601cc0 <_GLOBAL_OFFSET_TABLE_+0x10>
  40035c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400360 <__libc_start_main@plt>:
  400360:	ff 15 62 19 20 00    	callq  *0x201962(%rip)        # 601cc8 <_GLOBAL_OFFSET_TABLE_+0x18>
  400366:	68 00 00 00 00       	pushq  $0x0
  40036b:	e9 e0 ff ff ff       	jmpq   400350 <_init+0x20>

Disassembly of section .plt.got:

0000000000400370 <.plt.got>:
  400370:	ff 25 32 19 20 00    	jmpq   *0x201932(%rip)        # 601ca8 <_DYNAMIC+0x1d0>
  400376:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000400380 <_start>:
  400380:	31 ed                	xor    %ebp,%ebp
  400382:	49 89 d1             	mov    %rdx,%r9
  400385:	5e                   	pop    %rsi
  400386:	48 89 e2             	mov    %rsp,%rdx
  400389:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40038d:	50                   	push   %rax
  40038e:	54                   	push   %rsp
  40038f:	49 c7 c0 20 16 40 00 	mov    $0x401620,%r8
  400396:	48 c7 c1 b0 15 40 00 	mov    $0x4015b0,%rcx
  40039d:	48 c7 c7 f3 0c 40 00 	mov    $0x400cf3,%rdi
  4003a4:	e8 b7 ff ff ff       	callq  400360 <__libc_start_main@plt>
  4003a9:	f4                   	hlt    
  4003aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004003b0 <deregister_tm_clones>:
  4003b0:	b8 07 1d 60 00       	mov    $0x601d07,%eax
  4003b5:	55                   	push   %rbp
  4003b6:	48 2d 00 1d 60 00    	sub    $0x601d00,%rax
  4003bc:	48 83 f8 0e          	cmp    $0xe,%rax
  4003c0:	48 89 e5             	mov    %rsp,%rbp
  4003c3:	76 1b                	jbe    4003e0 <deregister_tm_clones+0x30>
  4003c5:	b8 00 00 00 00       	mov    $0x0,%eax
  4003ca:	48 85 c0             	test   %rax,%rax
  4003cd:	74 11                	je     4003e0 <deregister_tm_clones+0x30>
  4003cf:	5d                   	pop    %rbp
  4003d0:	bf 00 1d 60 00       	mov    $0x601d00,%edi
  4003d5:	ff e0                	jmpq   *%rax
  4003d7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  4003de:	00 00 
  4003e0:	5d                   	pop    %rbp
  4003e1:	c3                   	retq   
  4003e2:	0f 1f 40 00          	nopl   0x0(%rax)
  4003e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4003ed:	00 00 00 

00000000004003f0 <register_tm_clones>:
  4003f0:	be 00 1d 60 00       	mov    $0x601d00,%esi
  4003f5:	55                   	push   %rbp
  4003f6:	48 81 ee 00 1d 60 00 	sub    $0x601d00,%rsi
  4003fd:	48 c1 fe 03          	sar    $0x3,%rsi
  400401:	48 89 e5             	mov    %rsp,%rbp
  400404:	48 89 f0             	mov    %rsi,%rax
  400407:	48 c1 e8 3f          	shr    $0x3f,%rax
  40040b:	48 01 c6             	add    %rax,%rsi
  40040e:	48 d1 fe             	sar    %rsi
  400411:	74 15                	je     400428 <register_tm_clones+0x38>
  400413:	b8 00 00 00 00       	mov    $0x0,%eax
  400418:	48 85 c0             	test   %rax,%rax
  40041b:	74 0b                	je     400428 <register_tm_clones+0x38>
  40041d:	5d                   	pop    %rbp
  40041e:	bf 00 1d 60 00       	mov    $0x601d00,%edi
  400423:	ff e0                	jmpq   *%rax
  400425:	0f 1f 00             	nopl   (%rax)
  400428:	5d                   	pop    %rbp
  400429:	c3                   	retq   
  40042a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400430 <__do_global_dtors_aux>:
  400430:	80 3d c9 18 20 00 00 	cmpb   $0x0,0x2018c9(%rip)        # 601d00 <__TMC_END__>
  400437:	75 11                	jne    40044a <__do_global_dtors_aux+0x1a>
  400439:	55                   	push   %rbp
  40043a:	48 89 e5             	mov    %rsp,%rbp
  40043d:	e8 6e ff ff ff       	callq  4003b0 <deregister_tm_clones>
  400442:	5d                   	pop    %rbp
  400443:	c6 05 b6 18 20 00 01 	movb   $0x1,0x2018b6(%rip)        # 601d00 <__TMC_END__>
  40044a:	f3 c3                	repz retq 
  40044c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400450 <frame_dummy>:
  400450:	bf d0 1a 60 00       	mov    $0x601ad0,%edi
  400455:	48 83 3f 00          	cmpq   $0x0,(%rdi)
  400459:	75 05                	jne    400460 <frame_dummy+0x10>
  40045b:	eb 93                	jmp    4003f0 <register_tm_clones>
  40045d:	0f 1f 00             	nopl   (%rax)
  400460:	b8 00 00 00 00       	mov    $0x0,%eax
  400465:	48 85 c0             	test   %rax,%rax
  400468:	74 f1                	je     40045b <frame_dummy+0xb>
  40046a:	55                   	push   %rbp
  40046b:	48 89 e5             	mov    %rsp,%rbp
  40046e:	ff d0                	callq  *%rax
  400470:	5d                   	pop    %rbp
  400471:	e9 7a ff ff ff       	jmpq   4003f0 <register_tm_clones>

0000000000400476 <mov>:
  400476:	55                   	push   %rbp
  400477:	48 89 e5             	mov    %rsp,%rbp
  40047a:	48 83 ec 20          	sub    $0x20,%rsp
  40047e:	89 7d ec             	mov    %edi,-0x14(%rbp)
  400481:	89 75 e8             	mov    %esi,-0x18(%rbp)
  400484:	89 55 e4             	mov    %edx,-0x1c(%rbp)
  400487:	83 7d ec 01          	cmpl   $0x1,-0x14(%rbp)
  40048b:	75 4f                	jne    4004dc <mov+0x66>
  40048d:	8b 45 e8             	mov    -0x18(%rbp),%eax
  400490:	48 98                	cltq   
  400492:	8b 04 85 10 1d 60 00 	mov    0x601d10(,%rax,4),%eax
  400499:	8d 50 ff             	lea    -0x1(%rax),%edx
  40049c:	8b 45 e8             	mov    -0x18(%rbp),%eax
  40049f:	48 98                	cltq   
  4004a1:	89 14 85 10 1d 60 00 	mov    %edx,0x601d10(,%rax,4)
  4004a8:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4004ab:	48 98                	cltq   
  4004ad:	8b 04 85 10 1d 60 00 	mov    0x601d10(,%rax,4),%eax
  4004b4:	8d 50 01             	lea    0x1(%rax),%edx
  4004b7:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4004ba:	48 98                	cltq   
  4004bc:	89 14 85 10 1d 60 00 	mov    %edx,0x601d10(,%rax,4)
  4004c3:	48 8b 05 56 18 20 00 	mov    0x201856(%rip),%rax        # 601d20 <count>
  4004ca:	48 83 c0 01          	add    $0x1,%rax
  4004ce:	48 89 05 4b 18 20 00 	mov    %rax,0x20184b(%rip)        # 601d20 <count>
  4004d5:	b8 00 00 00 00       	mov    $0x0,%eax
  4004da:	eb 55                	jmp    400531 <_CDI_benchmark.s.mov_TO_benchmark.s.mov_3+0x5>
  4004dc:	8b 55 e8             	mov    -0x18(%rbp),%edx
  4004df:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4004e2:	01 d0                	add    %edx,%eax
  4004e4:	ba 06 00 00 00       	mov    $0x6,%edx
  4004e9:	29 c2                	sub    %eax,%edx
  4004eb:	89 d0                	mov    %edx,%eax
  4004ed:	89 45 fc             	mov    %eax,-0x4(%rbp)
  4004f0:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4004f3:	8d 48 ff             	lea    -0x1(%rax),%ecx
  4004f6:	8b 55 fc             	mov    -0x4(%rbp),%edx
  4004f9:	8b 45 e8             	mov    -0x18(%rbp),%eax
  4004fc:	89 c6                	mov    %eax,%esi
  4004fe:	89 cf                	mov    %ecx,%edi
  400500:	e8 71 ff ff ff       	callq  400476 <mov>

0000000000400505 <_CDI_benchmark.s.mov_TO_benchmark.s.mov_1>:
  400505:	8b 55 e4             	mov    -0x1c(%rbp),%edx
  400508:	8b 45 e8             	mov    -0x18(%rbp),%eax
  40050b:	89 c6                	mov    %eax,%esi
  40050d:	bf 01 00 00 00       	mov    $0x1,%edi
  400512:	e8 5f ff ff ff       	callq  400476 <mov>

0000000000400517 <_CDI_benchmark.s.mov_TO_benchmark.s.mov_2>:
  400517:	8b 45 ec             	mov    -0x14(%rbp),%eax
  40051a:	8d 48 ff             	lea    -0x1(%rax),%ecx
  40051d:	8b 55 e4             	mov    -0x1c(%rbp),%edx
  400520:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400523:	89 c6                	mov    %eax,%esi
  400525:	89 cf                	mov    %ecx,%edi
  400527:	e8 4a ff ff ff       	callq  400476 <mov>

000000000040052c <_CDI_benchmark.s.mov_TO_benchmark.s.mov_3>:
  40052c:	b8 00 00 00 00       	mov    $0x0,%eax
  400531:	c9                   	leaveq 
  400532:	48 83 c4 08          	add    $0x8,%rsp
  400536:	48 81 7c 24 f8 37 06 	cmpq   $0x400637,-0x8(%rsp)
  40053d:	40 00 
  40053f:	0f 84 f2 00 00 00    	je     400637 <_CDI_benchmark.s.mov_TO_benchmark.s.hanoi_main_1>
  400545:	48 81 7c 24 f8 9d 09 	cmpq   $0x40099d,-0x8(%rsp)
  40054c:	40 00 
  40054e:	0f 84 49 04 00 00    	je     40099d <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_1>
  400554:	48 81 7c 24 f8 cf 0a 	cmpq   $0x400acf,-0x8(%rsp)
  40055b:	40 00 
  40055d:	0f 84 6c 05 00 00    	je     400acf <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_2>
  400563:	48 81 7c 24 f8 05 05 	cmpq   $0x400505,-0x8(%rsp)
  40056a:	40 00 
  40056c:	74 97                	je     400505 <_CDI_benchmark.s.mov_TO_benchmark.s.mov_1>
  40056e:	48 81 7c 24 f8 17 05 	cmpq   $0x400517,-0x8(%rsp)
  400575:	40 00 
  400577:	74 9e                	je     400517 <_CDI_benchmark.s.mov_TO_benchmark.s.mov_2>
  400579:	48 81 7c 24 f8 2c 05 	cmpq   $0x40052c,-0x8(%rsp)
  400580:	40 00 
  400582:	74 a8                	je     40052c <_CDI_benchmark.s.mov_TO_benchmark.s.mov_3>
  400584:	48 c7 c6 97 05 40 00 	mov    $0x400597,%rsi
  40058b:	48 c7 c2 22 00 00 00 	mov    $0x22,%rdx
  400592:	e8 bc 10 00 00       	callq  401653 <_CDI_abort>

0000000000400597 <.CDI_sled_id_1>:
  400597:	62                   	(bad)  
  400598:	65 6e                	outsb  %gs:(%rsi),(%dx)
  40059a:	63 68 6d             	movslq 0x6d(%rax),%ebp
  40059d:	61                   	(bad)  
  40059e:	72 6b                	jb     40060b <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_2+0x25>
  4005a0:	2e 63 3a             	movslq %cs:(%rdx),%edi
  4005a3:	32 36                	xor    (%rsi),%dh
  4005a5:	3a 30                	cmp    (%rax),%dh
  4005a7:	3a 62 65             	cmp    0x65(%rdx),%ah
  4005aa:	6e                   	outsb  %ds:(%rsi),(%dx)
  4005ab:	63 68 6d             	movslq 0x6d(%rax),%ebp
  4005ae:	61                   	(bad)  
  4005af:	72 6b                	jb     40061c <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_2+0x36>
  4005b1:	2e 73 20             	jae,pn 4005d4 <hanoi_main+0x1b>
  4005b4:	69 64 3d 31 00 55 48 	imul   $0x89485500,0x31(%rbp,%rdi,1),%esp
  4005bb:	89 

00000000004005b9 <hanoi_main>:
  4005b9:	55                   	push   %rbp
  4005ba:	48 89 e5             	mov    %rsp,%rbp
  4005bd:	48 83 ec 10          	sub    $0x10,%rsp
  4005c1:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  4005c8:	bf 00 17 40 00       	mov    $0x401700,%edi
  4005cd:	b8 00 00 00 00       	mov    $0x0,%eax
  4005d2:	e8 6c 0a 00 00       	callq  401043 <tfp_printf>

00000000004005d7 <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_1>:
  4005d7:	bf 25 17 40 00       	mov    $0x401725,%edi
  4005dc:	b8 00 00 00 00       	mov    $0x0,%eax
  4005e1:	e8 5d 0a 00 00       	callq  401043 <tfp_printf>

00000000004005e6 <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_2>:
  4005e6:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  4005ed:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  4005f1:	c7 05 15 17 20 00 00 	movl   $0x0,0x201715(%rip)        # 601d10 <num>
  4005f8:	00 00 00 
  4005fb:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005fe:	89 05 10 17 20 00    	mov    %eax,0x201710(%rip)        # 601d14 <num+0x4>
  400604:	c7 05 0a 17 20 00 00 	movl   $0x0,0x20170a(%rip)        # 601d18 <num+0x8>
  40060b:	00 00 00 
  40060e:	c7 05 04 17 20 00 00 	movl   $0x0,0x201704(%rip)        # 601d1c <num+0xc>
  400615:	00 00 00 
  400618:	48 c7 05 fd 16 20 00 	movq   $0x0,0x2016fd(%rip)        # 601d20 <count>
  40061f:	00 00 00 00 
  400623:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400626:	ba 03 00 00 00       	mov    $0x3,%edx
  40062b:	be 01 00 00 00       	mov    $0x1,%esi
  400630:	89 c7                	mov    %eax,%edi
  400632:	e8 3f fe ff ff       	callq  400476 <mov>

0000000000400637 <_CDI_benchmark.s.mov_TO_benchmark.s.hanoi_main_1>:
  400637:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  40063b:	48 8b 05 de 16 20 00 	mov    0x2016de(%rip),%rax        # 601d20 <count>
  400642:	0f b7 d0             	movzwl %ax,%edx
  400645:	48 8b 05 d4 16 20 00 	mov    0x2016d4(%rip),%rax        # 601d20 <count>
  40064c:	48 c1 f8 10          	sar    $0x10,%rax
  400650:	48 89 c6             	mov    %rax,%rsi
  400653:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400656:	48 89 d1             	mov    %rdx,%rcx
  400659:	48 89 f2             	mov    %rsi,%rdx
  40065c:	89 c6                	mov    %eax,%esi
  40065e:	bf 36 17 40 00       	mov    $0x401736,%edi
  400663:	b8 00 00 00 00       	mov    $0x0,%eax
  400668:	e8 d6 09 00 00       	callq  401043 <tfp_printf>

000000000040066d <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_3>:
  40066d:	83 7d fc 1e          	cmpl   $0x1e,-0x4(%rbp)
  400671:	74 05                	je     400678 <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_3+0xb>
  400673:	e9 75 ff ff ff       	jmpq   4005ed <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_2+0x7>
  400678:	90                   	nop
  400679:	b8 00 00 00 00       	mov    $0x0,%eax
  40067e:	c9                   	leaveq 
  40067f:	48 83 c4 08          	add    $0x8,%rsp
  400683:	48 81 7c 24 f8 fc 0c 	cmpq   $0x400cfc,-0x8(%rsp)
  40068a:	40 00 
  40068c:	0f 84 6a 06 00 00    	je     400cfc <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.main_1>
  400692:	48 81 7c 24 f8 33 0a 	cmpq   $0x400a33,-0x8(%rsp)
  400699:	40 00 
  40069b:	0f 84 92 03 00 00    	je     400a33 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_1>
  4006a1:	48 81 7c 24 f8 65 0b 	cmpq   $0x400b65,-0x8(%rsp)
  4006a8:	40 00 
  4006aa:	0f 84 b5 04 00 00    	je     400b65 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_2>
  4006b0:	48 c7 c6 c3 06 40 00 	mov    $0x4006c3,%rsi
  4006b7:	48 c7 c2 22 00 00 00 	mov    $0x22,%rdx
  4006be:	e8 90 0f 00 00       	callq  401653 <_CDI_abort>

00000000004006c3 <.CDI_sled_id_2>:
  4006c3:	62                   	(bad)  
  4006c4:	65 6e                	outsb  %gs:(%rsi),(%dx)
  4006c6:	63 68 6d             	movslq 0x6d(%rax),%ebp
  4006c9:	61                   	(bad)  
  4006ca:	72 6b                	jb     400737 <encipher+0x52>
  4006cc:	2e 63 3a             	movslq %cs:(%rdx),%edi
  4006cf:	35 35 3a 30 3a       	xor    $0x3a303a35,%eax
  4006d4:	62                   	(bad)  
  4006d5:	65 6e                	outsb  %gs:(%rsi),(%dx)
  4006d7:	63 68 6d             	movslq 0x6d(%rax),%ebp
  4006da:	61                   	(bad)  
  4006db:	72 6b                	jb     400748 <encipher+0x63>
  4006dd:	2e 73 20             	jae,pn 400700 <encipher+0x1b>
  4006e0:	69 64 3d 32 00 55 48 	imul   $0x89485500,0x32(%rbp,%rdi,1),%esp
  4006e7:	89 

00000000004006e5 <encipher>:
  4006e5:	55                   	push   %rbp
  4006e6:	48 89 e5             	mov    %rsp,%rbp
  4006e9:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
  4006ed:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
  4006f1:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
  4006f5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4006f9:	8b 00                	mov    (%rax),%eax
  4006fb:	89 45 fc             	mov    %eax,-0x4(%rbp)
  4006fe:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  400702:	8b 40 04             	mov    0x4(%rax),%eax
  400705:	89 45 f8             	mov    %eax,-0x8(%rbp)
  400708:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
  40070f:	c7 45 ec b9 79 37 9e 	movl   $0x9e3779b9,-0x14(%rbp)
  400716:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  40071a:	8b 00                	mov    (%rax),%eax
  40071c:	89 45 e8             	mov    %eax,-0x18(%rbp)
  40071f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  400723:	8b 40 04             	mov    0x4(%rax),%eax
  400726:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  400729:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  40072d:	8b 40 08             	mov    0x8(%rax),%eax
  400730:	89 45 e0             	mov    %eax,-0x20(%rbp)
  400733:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  400737:	8b 40 0c             	mov    0xc(%rax),%eax
  40073a:	89 45 dc             	mov    %eax,-0x24(%rbp)
  40073d:	c7 45 f0 20 00 00 00 	movl   $0x20,-0x10(%rbp)
  400744:	eb 5e                	jmp    4007a4 <encipher+0xbf>
  400746:	8b 45 ec             	mov    -0x14(%rbp),%eax
  400749:	01 45 f4             	add    %eax,-0xc(%rbp)
  40074c:	8b 45 f8             	mov    -0x8(%rbp),%eax
  40074f:	c1 e0 04             	shl    $0x4,%eax
  400752:	89 c2                	mov    %eax,%edx
  400754:	8b 45 e8             	mov    -0x18(%rbp),%eax
  400757:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
  40075a:	8b 55 f8             	mov    -0x8(%rbp),%edx
  40075d:	8b 45 f4             	mov    -0xc(%rbp),%eax
  400760:	01 d0                	add    %edx,%eax
  400762:	31 c1                	xor    %eax,%ecx
  400764:	89 ca                	mov    %ecx,%edx
  400766:	8b 45 f8             	mov    -0x8(%rbp),%eax
  400769:	c1 e8 05             	shr    $0x5,%eax
  40076c:	89 c1                	mov    %eax,%ecx
  40076e:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  400771:	01 c8                	add    %ecx,%eax
  400773:	31 d0                	xor    %edx,%eax
  400775:	01 45 fc             	add    %eax,-0x4(%rbp)
  400778:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40077b:	c1 e0 04             	shl    $0x4,%eax
  40077e:	89 c2                	mov    %eax,%edx
  400780:	8b 45 e0             	mov    -0x20(%rbp),%eax
  400783:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
  400786:	8b 55 fc             	mov    -0x4(%rbp),%edx
  400789:	8b 45 f4             	mov    -0xc(%rbp),%eax
  40078c:	01 d0                	add    %edx,%eax
  40078e:	31 c1                	xor    %eax,%ecx
  400790:	89 ca                	mov    %ecx,%edx
  400792:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400795:	c1 e8 05             	shr    $0x5,%eax
  400798:	89 c1                	mov    %eax,%ecx
  40079a:	8b 45 dc             	mov    -0x24(%rbp),%eax
  40079d:	01 c8                	add    %ecx,%eax
  40079f:	31 d0                	xor    %edx,%eax
  4007a1:	01 45 f8             	add    %eax,-0x8(%rbp)
  4007a4:	8b 45 f0             	mov    -0x10(%rbp),%eax
  4007a7:	8d 50 ff             	lea    -0x1(%rax),%edx
  4007aa:	89 55 f0             	mov    %edx,-0x10(%rbp)
  4007ad:	85 c0                	test   %eax,%eax
  4007af:	75 95                	jne    400746 <encipher+0x61>
  4007b1:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  4007b5:	8b 55 fc             	mov    -0x4(%rbp),%edx
  4007b8:	89 10                	mov    %edx,(%rax)
  4007ba:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  4007be:	48 8d 50 04          	lea    0x4(%rax),%rdx
  4007c2:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4007c5:	89 02                	mov    %eax,(%rdx)
  4007c7:	90                   	nop
  4007c8:	5d                   	pop    %rbp
  4007c9:	48 83 c4 08          	add    $0x8,%rsp
  4007cd:	48 81 7c 24 f8 f7 09 	cmpq   $0x4009f7,-0x8(%rsp)
  4007d4:	40 00 
  4007d6:	0f 84 1b 02 00 00    	je     4009f7 <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_1>
  4007dc:	48 81 7c 24 f8 29 0b 	cmpq   $0x400b29,-0x8(%rsp)
  4007e3:	40 00 
  4007e5:	0f 84 3e 03 00 00    	je     400b29 <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_2>
  4007eb:	48 c7 c6 fe 07 40 00 	mov    $0x4007fe,%rsi
  4007f2:	48 c7 c2 22 00 00 00 	mov    $0x22,%rdx
  4007f9:	e8 55 0e 00 00       	callq  401653 <_CDI_abort>

00000000004007fe <.CDI_sled_id_3>:
  4007fe:	62                   	(bad)  
  4007ff:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400801:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400804:	61                   	(bad)  
  400805:	72 6b                	jb     400872 <decipher+0x52>
  400807:	2e 63 3a             	movslq %cs:(%rdx),%edi
  40080a:	37                   	(bad)  
  40080b:	34 3a                	xor    $0x3a,%al
  40080d:	30 3a                	xor    %bh,(%rdx)
  40080f:	62                   	(bad)  
  400810:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400812:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400815:	61                   	(bad)  
  400816:	72 6b                	jb     400883 <decipher+0x63>
  400818:	2e 73 20             	jae,pn 40083b <decipher+0x1b>
  40081b:	69 64 3d 33 00 55 48 	imul   $0x89485500,0x33(%rbp,%rdi,1),%esp
  400822:	89 

0000000000400820 <decipher>:
  400820:	55                   	push   %rbp
  400821:	48 89 e5             	mov    %rsp,%rbp
  400824:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
  400828:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
  40082c:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
  400830:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  400834:	8b 00                	mov    (%rax),%eax
  400836:	89 45 fc             	mov    %eax,-0x4(%rbp)
  400839:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40083d:	8b 40 04             	mov    0x4(%rax),%eax
  400840:	89 45 f8             	mov    %eax,-0x8(%rbp)
  400843:	c7 45 f4 20 37 ef c6 	movl   $0xc6ef3720,-0xc(%rbp)
  40084a:	c7 45 ec b9 79 37 9e 	movl   $0x9e3779b9,-0x14(%rbp)
  400851:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  400855:	8b 00                	mov    (%rax),%eax
  400857:	89 45 e8             	mov    %eax,-0x18(%rbp)
  40085a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  40085e:	8b 40 04             	mov    0x4(%rax),%eax
  400861:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  400864:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  400868:	8b 40 08             	mov    0x8(%rax),%eax
  40086b:	89 45 e0             	mov    %eax,-0x20(%rbp)
  40086e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  400872:	8b 40 0c             	mov    0xc(%rax),%eax
  400875:	89 45 dc             	mov    %eax,-0x24(%rbp)
  400878:	c7 45 f0 20 00 00 00 	movl   $0x20,-0x10(%rbp)
  40087f:	eb 5e                	jmp    4008df <decipher+0xbf>
  400881:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400884:	c1 e0 04             	shl    $0x4,%eax
  400887:	89 c2                	mov    %eax,%edx
  400889:	8b 45 e0             	mov    -0x20(%rbp),%eax
  40088c:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
  40088f:	8b 55 fc             	mov    -0x4(%rbp),%edx
  400892:	8b 45 f4             	mov    -0xc(%rbp),%eax
  400895:	01 d0                	add    %edx,%eax
  400897:	31 c1                	xor    %eax,%ecx
  400899:	89 ca                	mov    %ecx,%edx
  40089b:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40089e:	c1 e8 05             	shr    $0x5,%eax
  4008a1:	89 c1                	mov    %eax,%ecx
  4008a3:	8b 45 dc             	mov    -0x24(%rbp),%eax
  4008a6:	01 c8                	add    %ecx,%eax
  4008a8:	31 d0                	xor    %edx,%eax
  4008aa:	29 45 f8             	sub    %eax,-0x8(%rbp)
  4008ad:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4008b0:	c1 e0 04             	shl    $0x4,%eax
  4008b3:	89 c2                	mov    %eax,%edx
  4008b5:	8b 45 e8             	mov    -0x18(%rbp),%eax
  4008b8:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
  4008bb:	8b 55 f8             	mov    -0x8(%rbp),%edx
  4008be:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4008c1:	01 d0                	add    %edx,%eax
  4008c3:	31 c1                	xor    %eax,%ecx
  4008c5:	89 ca                	mov    %ecx,%edx
  4008c7:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4008ca:	c1 e8 05             	shr    $0x5,%eax
  4008cd:	89 c1                	mov    %eax,%ecx
  4008cf:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4008d2:	01 c8                	add    %ecx,%eax
  4008d4:	31 d0                	xor    %edx,%eax
  4008d6:	29 45 fc             	sub    %eax,-0x4(%rbp)
  4008d9:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4008dc:	29 45 f4             	sub    %eax,-0xc(%rbp)
  4008df:	8b 45 f0             	mov    -0x10(%rbp),%eax
  4008e2:	8d 50 ff             	lea    -0x1(%rax),%edx
  4008e5:	89 55 f0             	mov    %edx,-0x10(%rbp)
  4008e8:	85 c0                	test   %eax,%eax
  4008ea:	75 95                	jne    400881 <decipher+0x61>
  4008ec:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  4008f0:	8b 55 fc             	mov    -0x4(%rbp),%edx
  4008f3:	89 10                	mov    %edx,(%rax)
  4008f5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  4008f9:	48 8d 50 04          	lea    0x4(%rax),%rdx
  4008fd:	8b 45 f8             	mov    -0x8(%rbp),%eax
  400900:	89 02                	mov    %eax,(%rdx)
  400902:	90                   	nop
  400903:	5d                   	pop    %rbp
  400904:	48 83 c4 08          	add    $0x8,%rsp
  400908:	48 81 7c 24 f8 e5 09 	cmpq   $0x4009e5,-0x8(%rsp)
  40090f:	40 00 
  400911:	0f 84 ce 00 00 00    	je     4009e5 <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_1>
  400917:	48 81 7c 24 f8 17 0b 	cmpq   $0x400b17,-0x8(%rsp)
  40091e:	40 00 
  400920:	0f 84 f1 01 00 00    	je     400b17 <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_2>
  400926:	48 c7 c6 39 09 40 00 	mov    $0x400939,%rsi
  40092d:	48 c7 c2 22 00 00 00 	mov    $0x22,%rdx
  400934:	e8 1a 0d 00 00       	callq  401653 <_CDI_abort>

0000000000400939 <.CDI_sled_id_4>:
  400939:	62                   	(bad)  
  40093a:	65 6e                	outsb  %gs:(%rsi),(%dx)
  40093c:	63 68 6d             	movslq 0x6d(%rax),%ebp
  40093f:	61                   	(bad)  
  400940:	72 6b                	jb     4009ad <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_1+0x10>
  400942:	2e 63 3a             	movslq %cs:(%rdx),%edi
  400945:	39 32                	cmp    %esi,(%rdx)
  400947:	3a 30                	cmp    (%rax),%dh
  400949:	3a 62 65             	cmp    0x65(%rdx),%ah
  40094c:	6e                   	outsb  %ds:(%rsi),(%dx)
  40094d:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400950:	61                   	(bad)  
  400951:	72 6b                	jb     4009be <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_1+0xf>
  400953:	2e 73 20             	jae,pn 400976 <cipher_main+0x1b>
  400956:	69 64 3d 34 00 55 48 	imul   $0x89485500,0x34(%rbp,%rdi,1),%esp
  40095d:	89 

000000000040095b <cipher_main>:
  40095b:	55                   	push   %rbp
  40095c:	48 89 e5             	mov    %rsp,%rbp
  40095f:	48 83 ec 10          	sub    $0x10,%rsp
  400963:	48 c7 45 f8 e5 06 40 	movq   $0x4006e5,-0x8(%rbp)
  40096a:	00 
  40096b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40096f:	ba e0 1c 60 00       	mov    $0x601ce0,%edx
  400974:	be 50 1d 60 00       	mov    $0x601d50,%esi
  400979:	bf f0 1c 60 00       	mov    $0x601cf0,%edi
  40097e:	48 3d 23 0f 40 00    	cmp    $0x400f23,%rax
  400984:	75 0a                	jne    400990 <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_1+0x5>
  400986:	e8 98 05 00 00       	callq  400f23 <divOut>

000000000040098b <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_1>:
  40098b:	e9 db 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  400990:	48 3d 76 04 40 00    	cmp    $0x400476,%rax
  400996:	75 0a                	jne    4009a2 <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_1+0x5>
  400998:	e8 d9 fa ff ff       	callq  400476 <mov>

000000000040099d <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_1>:
  40099d:	e9 c9 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  4009a2:	48 3d 5a 0e 40 00    	cmp    $0x400e5a,%rax
  4009a8:	75 0a                	jne    4009b4 <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_1+0x5>
  4009aa:	e8 ab 04 00 00       	callq  400e5a <outDgt>

00000000004009af <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_1>:
  4009af:	e9 b7 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  4009b4:	48 3d aa 0d 40 00    	cmp    $0x400daa,%rax
  4009ba:	75 0a                	jne    4009c6 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_1+0x5>
  4009bc:	e8 e9 03 00 00       	callq  400daa <out>

00000000004009c1 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_1>:
  4009c1:	e9 a5 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  4009c6:	48 3d f3 0c 40 00    	cmp    $0x400cf3,%rax
  4009cc:	75 0a                	jne    4009d8 <_CDI_benchmark.s.main_TO_benchmark.s.cipher_main_1+0x5>
  4009ce:	e8 20 03 00 00       	callq  400cf3 <main>

00000000004009d3 <_CDI_benchmark.s.main_TO_benchmark.s.cipher_main_1>:
  4009d3:	e9 93 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  4009d8:	48 3d 20 08 40 00    	cmp    $0x400820,%rax
  4009de:	75 0a                	jne    4009ea <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_1+0x5>
  4009e0:	e8 3b fe ff ff       	callq  400820 <decipher>

00000000004009e5 <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_1>:
  4009e5:	e9 81 00 00 00       	jmpq   400a6b <.CDI_sled_id_5+0x23>
  4009ea:	48 3d e5 06 40 00    	cmp    $0x4006e5,%rax
  4009f0:	75 07                	jne    4009f9 <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_1+0x2>
  4009f2:	e8 ee fc ff ff       	callq  4006e5 <encipher>

00000000004009f7 <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_1>:
  4009f7:	eb 72                	jmp    400a6b <.CDI_sled_id_5+0x23>
  4009f9:	48 3d 08 0d 40 00    	cmp    $0x400d08,%rax
  4009ff:	75 07                	jne    400a08 <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_1+0x2>
  400a01:	e8 02 03 00 00       	callq  400d08 <outchar>

0000000000400a06 <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_1>:
  400a06:	eb 63                	jmp    400a6b <.CDI_sled_id_5+0x23>
  400a08:	48 3d 43 10 40 00    	cmp    $0x401043,%rax
  400a0e:	75 07                	jne    400a17 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_1+0x2>
  400a10:	e8 2e 06 00 00       	callq  401043 <tfp_printf>

0000000000400a15 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_1>:
  400a15:	eb 54                	jmp    400a6b <.CDI_sled_id_5+0x23>
  400a17:	48 3d 5b 09 40 00    	cmp    $0x40095b,%rax
  400a1d:	75 07                	jne    400a26 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_1+0x2>
  400a1f:	e8 37 ff ff ff       	callq  40095b <cipher_main>

0000000000400a24 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_1>:
  400a24:	eb 45                	jmp    400a6b <.CDI_sled_id_5+0x23>
  400a26:	48 3d b9 05 40 00    	cmp    $0x4005b9,%rax
  400a2c:	75 07                	jne    400a35 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_1+0x2>
  400a2e:	e8 86 fb ff ff       	callq  4005b9 <hanoi_main>

0000000000400a33 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_1>:
  400a33:	eb 36                	jmp    400a6b <.CDI_sled_id_5+0x23>
  400a35:	48 c7 c6 48 0a 40 00 	mov    $0x400a48,%rsi
  400a3c:	48 c7 c2 23 00 00 00 	mov    $0x23,%rdx
  400a43:	e8 0b 0c 00 00       	callq  401653 <_CDI_abort>

0000000000400a48 <.CDI_sled_id_5>:
  400a48:	62                   	(bad)  
  400a49:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400a4b:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400a4e:	61                   	(bad)  
  400a4f:	72 6b                	jb     400abc <.CDI_sled_id_5+0x74>
  400a51:	2e 63 3a             	movslq %cs:(%rdx),%edi
  400a54:	31 30                	xor    %esi,(%rax)
  400a56:	38 3a                	cmp    %bh,(%rdx)
  400a58:	30 3a                	xor    %bh,(%rdx)
  400a5a:	62                   	(bad)  
  400a5b:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400a5d:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400a60:	61                   	(bad)  
  400a61:	72 6b                	jb     400ace <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_2+0x11>
  400a63:	2e 73 20             	jae,pn 400a86 <.CDI_sled_id_5+0x3e>
  400a66:	69 64 3d 35 00 8b 15 	imul   $0xdf158b00,0x35(%rbp,%rdi,1),%esp
  400a6d:	df 
  400a6e:	12 20                	adc    (%rax),%ah
  400a70:	00 8b 05 81 12 20    	add    %cl,0x20128105(%rbx)
  400a76:	00 39                	add    %bh,(%rcx)
  400a78:	c2 75 10             	retq   $0x1075
  400a7b:	8b 15 d3 12 20 00    	mov    0x2012d3(%rip),%edx        # 601d54 <ciphertext+0x4>
  400a81:	8b 05 75 12 20 00    	mov    0x201275(%rip),%eax        # 601cfc <cipherref+0x4>
  400a87:	39 c2                	cmp    %eax,%edx
  400a89:	74 0a                	je     400a95 <.CDI_sled_id_5+0x4d>
  400a8b:	b8 01 00 00 00       	mov    $0x1,%eax
  400a90:	e9 fa 01 00 00       	jmpq   400c8f <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_6+0x5>
  400a95:	48 c7 45 f8 20 08 40 	movq   $0x400820,-0x8(%rbp)
  400a9c:	00 
  400a9d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400aa1:	ba e0 1c 60 00       	mov    $0x601ce0,%edx
  400aa6:	be 48 1d 60 00       	mov    $0x601d48,%esi
  400aab:	bf 50 1d 60 00       	mov    $0x601d50,%edi
  400ab0:	48 3d 23 0f 40 00    	cmp    $0x400f23,%rax
  400ab6:	75 0a                	jne    400ac2 <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_2+0x5>
  400ab8:	e8 66 04 00 00       	callq  400f23 <divOut>

0000000000400abd <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_2>:
  400abd:	e9 db 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400ac2:	48 3d 76 04 40 00    	cmp    $0x400476,%rax
  400ac8:	75 0a                	jne    400ad4 <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_2+0x5>
  400aca:	e8 a7 f9 ff ff       	callq  400476 <mov>

0000000000400acf <_CDI_benchmark.s.mov_TO_benchmark.s.cipher_main_2>:
  400acf:	e9 c9 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400ad4:	48 3d 5a 0e 40 00    	cmp    $0x400e5a,%rax
  400ada:	75 0a                	jne    400ae6 <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_2+0x5>
  400adc:	e8 79 03 00 00       	callq  400e5a <outDgt>

0000000000400ae1 <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_2>:
  400ae1:	e9 b7 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400ae6:	48 3d aa 0d 40 00    	cmp    $0x400daa,%rax
  400aec:	75 0a                	jne    400af8 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_2+0x5>
  400aee:	e8 b7 02 00 00       	callq  400daa <out>

0000000000400af3 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_2>:
  400af3:	e9 a5 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400af8:	48 3d f3 0c 40 00    	cmp    $0x400cf3,%rax
  400afe:	75 0a                	jne    400b0a <_CDI_benchmark.s.main_TO_benchmark.s.cipher_main_2+0x5>
  400b00:	e8 ee 01 00 00       	callq  400cf3 <main>

0000000000400b05 <_CDI_benchmark.s.main_TO_benchmark.s.cipher_main_2>:
  400b05:	e9 93 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400b0a:	48 3d 20 08 40 00    	cmp    $0x400820,%rax
  400b10:	75 0a                	jne    400b1c <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_2+0x5>
  400b12:	e8 09 fd ff ff       	callq  400820 <decipher>

0000000000400b17 <_CDI_benchmark.s.decipher_TO_benchmark.s.cipher_main_2>:
  400b17:	e9 81 00 00 00       	jmpq   400b9d <.CDI_sled_id_6+0x23>
  400b1c:	48 3d e5 06 40 00    	cmp    $0x4006e5,%rax
  400b22:	75 07                	jne    400b2b <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_2+0x2>
  400b24:	e8 bc fb ff ff       	callq  4006e5 <encipher>

0000000000400b29 <_CDI_benchmark.s.encipher_TO_benchmark.s.cipher_main_2>:
  400b29:	eb 72                	jmp    400b9d <.CDI_sled_id_6+0x23>
  400b2b:	48 3d 08 0d 40 00    	cmp    $0x400d08,%rax
  400b31:	75 07                	jne    400b3a <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_2+0x2>
  400b33:	e8 d0 01 00 00       	callq  400d08 <outchar>

0000000000400b38 <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_2>:
  400b38:	eb 63                	jmp    400b9d <.CDI_sled_id_6+0x23>
  400b3a:	48 3d 43 10 40 00    	cmp    $0x401043,%rax
  400b40:	75 07                	jne    400b49 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_2+0x2>
  400b42:	e8 fc 04 00 00       	callq  401043 <tfp_printf>

0000000000400b47 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_2>:
  400b47:	eb 54                	jmp    400b9d <.CDI_sled_id_6+0x23>
  400b49:	48 3d 5b 09 40 00    	cmp    $0x40095b,%rax
  400b4f:	75 07                	jne    400b58 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_2+0x2>
  400b51:	e8 05 fe ff ff       	callq  40095b <cipher_main>

0000000000400b56 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_2>:
  400b56:	eb 45                	jmp    400b9d <.CDI_sled_id_6+0x23>
  400b58:	48 3d b9 05 40 00    	cmp    $0x4005b9,%rax
  400b5e:	75 07                	jne    400b67 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_2+0x2>
  400b60:	e8 54 fa ff ff       	callq  4005b9 <hanoi_main>

0000000000400b65 <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.cipher_main_2>:
  400b65:	eb 36                	jmp    400b9d <.CDI_sled_id_6+0x23>
  400b67:	48 c7 c6 7a 0b 40 00 	mov    $0x400b7a,%rsi
  400b6e:	48 c7 c2 23 00 00 00 	mov    $0x23,%rdx
  400b75:	e8 d9 0a 00 00       	callq  401653 <_CDI_abort>

0000000000400b7a <.CDI_sled_id_6>:
  400b7a:	62                   	(bad)  
  400b7b:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400b7d:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400b80:	61                   	(bad)  
  400b81:	72 6b                	jb     400bee <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_3+0x18>
  400b83:	2e 63 3a             	movslq %cs:(%rdx),%edi
  400b86:	31 31                	xor    %esi,(%rcx)
  400b88:	32 3a                	xor    (%rdx),%bh
  400b8a:	30 3a                	xor    %bh,(%rdx)
  400b8c:	62                   	(bad)  
  400b8d:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400b8f:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400b92:	61                   	(bad)  
  400b93:	72 6b                	jb     400c00 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_3+0x2a>
  400b95:	2e 73 20             	jae,pn 400bb8 <.CDI_sled_id_6+0x3e>
  400b98:	69 64 3d 36 00 8b 15 	imul   $0xa5158b00,0x36(%rbp,%rdi,1),%esp
  400b9f:	a5 
  400ba0:	11 20                	adc    %esp,(%rax)
  400ba2:	00 8b 05 47 11 20    	add    %cl,0x20114705(%rbx)
  400ba8:	00 39                	add    %bh,(%rcx)
  400baa:	c2 75 10             	retq   $0x1075
  400bad:	8b 15 99 11 20 00    	mov    0x201199(%rip),%edx        # 601d4c <newplain+0x4>
  400bb3:	8b 05 3b 11 20 00    	mov    0x20113b(%rip),%eax        # 601cf4 <plaintext+0x4>
  400bb9:	39 c2                	cmp    %eax,%edx
  400bbb:	74 0a                	je     400bc7 <.CDI_sled_id_6+0x4d>
  400bbd:	b8 01 00 00 00       	mov    $0x1,%eax
  400bc2:	e9 c8 00 00 00       	jmpq   400c8f <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_6+0x5>
  400bc7:	bf 45 17 40 00       	mov    $0x401745,%edi
  400bcc:	b8 00 00 00 00       	mov    $0x0,%eax
  400bd1:	e8 6d 04 00 00       	callq  401043 <tfp_printf>

0000000000400bd6 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_3>:
  400bd6:	8b 05 18 11 20 00    	mov    0x201118(%rip),%eax        # 601cf4 <plaintext+0x4>
  400bdc:	0f b7 c8             	movzwl %ax,%ecx
  400bdf:	8b 05 0f 11 20 00    	mov    0x20110f(%rip),%eax        # 601cf4 <plaintext+0x4>
  400be5:	c1 e8 10             	shr    $0x10,%eax
  400be8:	89 c2                	mov    %eax,%edx
  400bea:	8b 05 00 11 20 00    	mov    0x201100(%rip),%eax        # 601cf0 <plaintext>
  400bf0:	0f b7 c0             	movzwl %ax,%eax
  400bf3:	8b 35 f7 10 20 00    	mov    0x2010f7(%rip),%esi        # 601cf0 <plaintext>
  400bf9:	c1 ee 10             	shr    $0x10,%esi
  400bfc:	41 89 c8             	mov    %ecx,%r8d
  400bff:	89 d1                	mov    %edx,%ecx
  400c01:	89 c2                	mov    %eax,%edx
  400c03:	bf 60 17 40 00       	mov    $0x401760,%edi
  400c08:	b8 00 00 00 00       	mov    $0x0,%eax
  400c0d:	e8 31 04 00 00       	callq  401043 <tfp_printf>

0000000000400c12 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_4>:
  400c12:	8b 05 3c 11 20 00    	mov    0x20113c(%rip),%eax        # 601d54 <ciphertext+0x4>
  400c18:	0f b7 c8             	movzwl %ax,%ecx
  400c1b:	8b 05 33 11 20 00    	mov    0x201133(%rip),%eax        # 601d54 <ciphertext+0x4>
  400c21:	c1 e8 10             	shr    $0x10,%eax
  400c24:	89 c2                	mov    %eax,%edx
  400c26:	8b 05 24 11 20 00    	mov    0x201124(%rip),%eax        # 601d50 <ciphertext>
  400c2c:	0f b7 c0             	movzwl %ax,%eax
  400c2f:	8b 35 1b 11 20 00    	mov    0x20111b(%rip),%esi        # 601d50 <ciphertext>
  400c35:	c1 ee 10             	shr    $0x10,%esi
  400c38:	41 89 c8             	mov    %ecx,%r8d
  400c3b:	89 d1                	mov    %edx,%ecx
  400c3d:	89 c2                	mov    %eax,%edx
  400c3f:	bf 88 17 40 00       	mov    $0x401788,%edi
  400c44:	b8 00 00 00 00       	mov    $0x0,%eax
  400c49:	e8 f5 03 00 00       	callq  401043 <tfp_printf>

0000000000400c4e <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_5>:
  400c4e:	8b 05 f8 10 20 00    	mov    0x2010f8(%rip),%eax        # 601d4c <newplain+0x4>
  400c54:	0f b7 c8             	movzwl %ax,%ecx
  400c57:	8b 05 ef 10 20 00    	mov    0x2010ef(%rip),%eax        # 601d4c <newplain+0x4>
  400c5d:	c1 e8 10             	shr    $0x10,%eax
  400c60:	89 c2                	mov    %eax,%edx
  400c62:	8b 05 e0 10 20 00    	mov    0x2010e0(%rip),%eax        # 601d48 <newplain>
  400c68:	0f b7 c0             	movzwl %ax,%eax
  400c6b:	8b 35 d7 10 20 00    	mov    0x2010d7(%rip),%esi        # 601d48 <newplain>
  400c71:	c1 ee 10             	shr    $0x10,%esi
  400c74:	41 89 c8             	mov    %ecx,%r8d
  400c77:	89 d1                	mov    %edx,%ecx
  400c79:	89 c2                	mov    %eax,%edx
  400c7b:	bf b0 17 40 00       	mov    $0x4017b0,%edi
  400c80:	b8 00 00 00 00       	mov    $0x0,%eax
  400c85:	e8 b9 03 00 00       	callq  401043 <tfp_printf>

0000000000400c8a <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_6>:
  400c8a:	b8 00 00 00 00       	mov    $0x0,%eax
  400c8f:	c9                   	leaveq 
  400c90:	48 83 c4 08          	add    $0x8,%rsp
  400c94:	48 81 7c 24 f8 01 0d 	cmpq   $0x400d01,-0x8(%rsp)
  400c9b:	40 00 
  400c9d:	74 62                	je     400d01 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.main_1>
  400c9f:	48 81 7c 24 f8 24 0a 	cmpq   $0x400a24,-0x8(%rsp)
  400ca6:	40 00 
  400ca8:	0f 84 76 fd ff ff    	je     400a24 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_1>
  400cae:	48 81 7c 24 f8 56 0b 	cmpq   $0x400b56,-0x8(%rsp)
  400cb5:	40 00 
  400cb7:	0f 84 99 fe ff ff    	je     400b56 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.cipher_main_2>
  400cbd:	48 c7 c6 d0 0c 40 00 	mov    $0x400cd0,%rsi
  400cc4:	48 c7 c2 23 00 00 00 	mov    $0x23,%rdx
  400ccb:	e8 83 09 00 00       	callq  401653 <_CDI_abort>

0000000000400cd0 <.CDI_sled_id_7>:
  400cd0:	62                   	(bad)  
  400cd1:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400cd3:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400cd6:	61                   	(bad)  
  400cd7:	72 6b                	jb     400d44 <outchar+0x3c>
  400cd9:	2e 63 3a             	movslq %cs:(%rdx),%edi
  400cdc:	31 32                	xor    %esi,(%rdx)
  400cde:	38 3a                	cmp    %bh,(%rdx)
  400ce0:	30 3a                	xor    %bh,(%rdx)
  400ce2:	62                   	(bad)  
  400ce3:	65 6e                	outsb  %gs:(%rsi),(%dx)
  400ce5:	63 68 6d             	movslq 0x6d(%rax),%ebp
  400ce8:	61                   	(bad)  
  400ce9:	72 6b                	jb     400d56 <outchar+0x4e>
  400ceb:	2e 73 20             	jae,pn 400d0e <outchar+0x6>
  400cee:	69 64 3d 37 00 55 48 	imul   $0x89485500,0x37(%rbp,%rdi,1),%esp
  400cf5:	89 

0000000000400cf3 <main>:
  400cf3:	55                   	push   %rbp
  400cf4:	48 89 e5             	mov    %rsp,%rbp
  400cf7:	e8 bd f8 ff ff       	callq  4005b9 <hanoi_main>

0000000000400cfc <_CDI_benchmark.s.hanoi_main_TO_benchmark.s.main_1>:
  400cfc:	e8 5a fc ff ff       	callq  40095b <cipher_main>

0000000000400d01 <_CDI_benchmark.s.cipher_main_TO_benchmark.s.main_1>:
  400d01:	b8 00 00 00 00       	mov    $0x0,%eax
  400d06:	5d                   	pop    %rbp
  400d07:	c3                   	retq   

0000000000400d08 <outchar>:
  400d08:	55                   	push   %rbp
  400d09:	48 89 e5             	mov    %rsp,%rbp
  400d0c:	89 f8                	mov    %edi,%eax
  400d0e:	88 45 fc             	mov    %al,-0x4(%rbp)
  400d11:	b8 01 00 00 00       	mov    $0x1,%eax
  400d16:	bf 01 00 00 00       	mov    $0x1,%edi
  400d1b:	48 8d 4d fc          	lea    -0x4(%rbp),%rcx
  400d1f:	ba 01 00 00 00       	mov    $0x1,%edx
  400d24:	48 89 ce             	mov    %rcx,%rsi
  400d27:	0f 05                	syscall 
  400d29:	90                   	nop
  400d2a:	5d                   	pop    %rbp
  400d2b:	48 83 c4 08          	add    $0x8,%rsp
  400d2f:	48 81 7c 24 f8 e5 10 	cmpq   $0x4010e5,-0x8(%rsp)
  400d36:	40 00 
  400d38:	0f 84 a7 03 00 00    	je     4010e5 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1>
  400d3e:	48 81 7c 24 f8 7b 14 	cmpq   $0x40147b,-0x8(%rsp)
  400d45:	40 00 
  400d47:	0f 84 2e 07 00 00    	je     40147b <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_2>
  400d4d:	48 81 7c 24 f8 a1 14 	cmpq   $0x4014a1,-0x8(%rsp)
  400d54:	40 00 
  400d56:	0f 84 45 07 00 00    	je     4014a1 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3>
  400d5c:	48 81 7c 24 f8 06 0a 	cmpq   $0x400a06,-0x8(%rsp)
  400d63:	40 00 
  400d65:	0f 84 9b fc ff ff    	je     400a06 <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_1>
  400d6b:	48 81 7c 24 f8 38 0b 	cmpq   $0x400b38,-0x8(%rsp)
  400d72:	40 00 
  400d74:	0f 84 be fd ff ff    	je     400b38 <_CDI_printf.s.outchar_TO_benchmark.s.cipher_main_2>
  400d7a:	48 c7 c6 8d 0d 40 00 	mov    $0x400d8d,%rsi
  400d81:	48 c7 c2 1d 00 00 00 	mov    $0x1d,%rdx
  400d88:	e8 c6 08 00 00       	callq  401653 <_CDI_abort>

0000000000400d8d <.CDI_sled_id_8>:
  400d8d:	6f                   	outsl  %ds:(%rsi),(%dx)
  400d8e:	75 74                	jne    400e04 <out+0x5a>
  400d90:	63 68 61             	movslq 0x61(%rax),%ebp
  400d93:	72 2e                	jb     400dc3 <out+0x19>
  400d95:	68 3a 31 30 3a       	pushq  $0x3a30313a
  400d9a:	30 3a                	xor    %bh,(%rdx)
  400d9c:	70 72                	jo     400e10 <out+0x66>
  400d9e:	69 6e 74 66 2e 73 20 	imul   $0x20732e66,0x74(%rsi),%ebp
  400da5:	69 64 3d 38 00 55 48 	imul   $0x89485500,0x38(%rbp,%rdi,1),%esp
  400dac:	89 

0000000000400daa <out>:
  400daa:	55                   	push   %rbp
  400dab:	48 89 e5             	mov    %rsp,%rbp
  400dae:	89 f8                	mov    %edi,%eax
  400db0:	88 45 fc             	mov    %al,-0x4(%rbp)
  400db3:	48 8b 05 6e 0f 20 00 	mov    0x200f6e(%rip),%rax        # 601d28 <bf>
  400dba:	48 8d 50 01          	lea    0x1(%rax),%rdx
  400dbe:	48 89 15 63 0f 20 00 	mov    %rdx,0x200f63(%rip)        # 601d28 <bf>
  400dc5:	0f b6 55 fc          	movzbl -0x4(%rbp),%edx
  400dc9:	88 10                	mov    %dl,(%rax)
  400dcb:	90                   	nop
  400dcc:	5d                   	pop    %rbp
  400dcd:	48 83 c4 08          	add    $0x8,%rsp
  400dd1:	48 81 7c 24 f8 9b 0e 	cmpq   $0x400e9b,-0x8(%rsp)
  400dd8:	40 00 
  400dda:	0f 84 bb 00 00 00    	je     400e9b <_CDI_printf.s.out_TO_printf.s.outDgt_1>
  400de0:	48 81 7c 24 f8 a4 12 	cmpq   $0x4012a4,-0x8(%rsp)
  400de7:	40 00 
  400de9:	0f 84 b5 04 00 00    	je     4012a4 <_CDI_printf.s.out_TO_printf.s.tfp_printf_1>
  400def:	48 81 7c 24 f8 b8 13 	cmpq   $0x4013b8,-0x8(%rsp)
  400df6:	40 00 
  400df8:	0f 84 ba 05 00 00    	je     4013b8 <_CDI_printf.s.out_TO_printf.s.tfp_printf_2>
  400dfe:	48 81 7c 24 f8 10 14 	cmpq   $0x401410,-0x8(%rsp)
  400e05:	40 00 
  400e07:	0f 84 03 06 00 00    	je     401410 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3>
  400e0d:	48 81 7c 24 f8 c1 09 	cmpq   $0x4009c1,-0x8(%rsp)
  400e14:	40 00 
  400e16:	0f 84 a5 fb ff ff    	je     4009c1 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_1>
  400e1c:	48 81 7c 24 f8 f3 0a 	cmpq   $0x400af3,-0x8(%rsp)
  400e23:	40 00 
  400e25:	0f 84 c8 fc ff ff    	je     400af3 <_CDI_printf.s.out_TO_benchmark.s.cipher_main_2>
  400e2b:	48 c7 c6 3e 0e 40 00 	mov    $0x400e3e,%rsi
  400e32:	48 c7 c2 1c 00 00 00 	mov    $0x1c,%rdx
  400e39:	e8 15 08 00 00       	callq  401653 <_CDI_abort>

0000000000400e3e <.CDI_sled_id_9>:
  400e3e:	70 72                	jo     400eb2 <_CDI_printf.s.out_TO_printf.s.outDgt_1+0x17>
  400e40:	69 6e 74 66 2e 63 3a 	imul   $0x3a632e66,0x74(%rsi),%ebp
  400e47:	35 31 3a 30 3a       	xor    $0x3a303a31,%eax
  400e4c:	70 72                	jo     400ec0 <_CDI_printf.s.out_TO_printf.s.outDgt_1+0x25>
  400e4e:	69 6e 74 66 2e 73 20 	imul   $0x20732e66,0x74(%rsi),%ebp
  400e55:	69 64 3d 39 00 55 48 	imul   $0x89485500,0x39(%rbp,%rdi,1),%esp
  400e5c:	89 

0000000000400e5a <outDgt>:
  400e5a:	55                   	push   %rbp
  400e5b:	48 89 e5             	mov    %rsp,%rbp
  400e5e:	48 83 ec 08          	sub    $0x8,%rsp
  400e62:	89 f8                	mov    %edi,%eax
  400e64:	88 45 fc             	mov    %al,-0x4(%rbp)
  400e67:	80 7d fc 09          	cmpb   $0x9,-0x4(%rbp)
  400e6b:	7e 19                	jle    400e86 <outDgt+0x2c>
  400e6d:	0f b6 05 cc 0e 20 00 	movzbl 0x200ecc(%rip),%eax        # 601d40 <uc>
  400e74:	84 c0                	test   %al,%al
  400e76:	74 07                	je     400e7f <outDgt+0x25>
  400e78:	b8 37 00 00 00       	mov    $0x37,%eax
  400e7d:	eb 0c                	jmp    400e8b <outDgt+0x31>
  400e7f:	b8 57 00 00 00       	mov    $0x57,%eax
  400e84:	eb 05                	jmp    400e8b <outDgt+0x31>
  400e86:	b8 30 00 00 00       	mov    $0x30,%eax
  400e8b:	0f b6 55 fc          	movzbl -0x4(%rbp),%edx
  400e8f:	01 d0                	add    %edx,%eax
  400e91:	0f be c0             	movsbl %al,%eax
  400e94:	89 c7                	mov    %eax,%edi
  400e96:	e8 0f ff ff ff       	callq  400daa <out>

0000000000400e9b <_CDI_printf.s.out_TO_printf.s.outDgt_1>:
  400e9b:	c6 05 9f 0e 20 00 01 	movb   $0x1,0x200e9f(%rip)        # 601d41 <zs>
  400ea2:	90                   	nop
  400ea3:	c9                   	leaveq 
  400ea4:	48 83 c4 08          	add    $0x8,%rsp
  400ea8:	48 81 7c 24 f8 dc 12 	cmpq   $0x4012dc,-0x8(%rsp)
  400eaf:	40 00 
  400eb1:	0f 84 25 04 00 00    	je     4012dc <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1>
  400eb7:	48 81 7c 24 f8 67 13 	cmpq   $0x401367,-0x8(%rsp)
  400ebe:	40 00 
  400ec0:	0f 84 a1 04 00 00    	je     401367 <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_2>
  400ec6:	48 81 7c 24 f8 86 0f 	cmpq   $0x400f86,-0x8(%rsp)
  400ecd:	40 00 
  400ecf:	0f 84 b1 00 00 00    	je     400f86 <_CDI_printf.s.outDgt_TO_printf.s.divOut_1>
  400ed5:	48 81 7c 24 f8 af 09 	cmpq   $0x4009af,-0x8(%rsp)
  400edc:	40 00 
  400ede:	0f 84 cb fa ff ff    	je     4009af <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_1>
  400ee4:	48 81 7c 24 f8 e1 0a 	cmpq   $0x400ae1,-0x8(%rsp)
  400eeb:	40 00 
  400eed:	0f 84 ee fb ff ff    	je     400ae1 <_CDI_printf.s.outDgt_TO_benchmark.s.cipher_main_2>
  400ef3:	48 c7 c6 06 0f 40 00 	mov    $0x400f06,%rsi
  400efa:	48 c7 c2 1d 00 00 00 	mov    $0x1d,%rdx
  400f01:	e8 4d 07 00 00       	callq  401653 <_CDI_abort>

0000000000400f06 <.CDI_sled_id_10>:
  400f06:	70 72                	jo     400f7a <divOut+0x57>
  400f08:	69 6e 74 66 2e 63 3a 	imul   $0x3a632e66,0x74(%rsi),%ebp
  400f0f:	35 36 3a 30 3a       	xor    $0x3a303a36,%eax
  400f14:	70 72                	jo     400f88 <_CDI_printf.s.outDgt_TO_printf.s.divOut_1+0x2>
  400f16:	69 6e 74 66 2e 73 20 	imul   $0x20732e66,0x74(%rsi),%ebp
  400f1d:	69 64 3d 31 30 00 55 	imul   $0x48550030,0x31(%rbp,%rdi,1),%esp
  400f24:	48 

0000000000400f23 <divOut>:
  400f23:	55                   	push   %rbp
  400f24:	48 89 e5             	mov    %rsp,%rbp
  400f27:	48 83 ec 18          	sub    $0x18,%rsp
  400f2b:	89 7d ec             	mov    %edi,-0x14(%rbp)
  400f2e:	c6 45 ff 00          	movb   $0x0,-0x1(%rbp)
  400f32:	8b 05 04 0e 20 00    	mov    0x200e04(%rip),%eax        # 601d3c <num>
  400f38:	0f b7 c0             	movzwl %ax,%eax
  400f3b:	89 05 fb 0d 20 00    	mov    %eax,0x200dfb(%rip)        # 601d3c <num>
  400f41:	eb 19                	jmp    400f5c <divOut+0x39>
  400f43:	8b 05 f3 0d 20 00    	mov    0x200df3(%rip),%eax        # 601d3c <num>
  400f49:	2b 45 ec             	sub    -0x14(%rbp),%eax
  400f4c:	89 05 ea 0d 20 00    	mov    %eax,0x200dea(%rip)        # 601d3c <num>
  400f52:	0f b6 45 ff          	movzbl -0x1(%rbp),%eax
  400f56:	83 c0 01             	add    $0x1,%eax
  400f59:	88 45 ff             	mov    %al,-0x1(%rbp)
  400f5c:	8b 05 da 0d 20 00    	mov    0x200dda(%rip),%eax        # 601d3c <num>
  400f62:	3b 45 ec             	cmp    -0x14(%rbp),%eax
  400f65:	73 dc                	jae    400f43 <divOut+0x20>
  400f67:	0f b6 05 d3 0d 20 00 	movzbl 0x200dd3(%rip),%eax        # 601d41 <zs>
  400f6e:	84 c0                	test   %al,%al
  400f70:	75 06                	jne    400f78 <divOut+0x55>
  400f72:	80 7d ff 00          	cmpb   $0x0,-0x1(%rbp)
  400f76:	74 0e                	je     400f86 <_CDI_printf.s.outDgt_TO_printf.s.divOut_1>
  400f78:	0f b6 45 ff          	movzbl -0x1(%rbp),%eax
  400f7c:	0f be c0             	movsbl %al,%eax
  400f7f:	89 c7                	mov    %eax,%edi
  400f81:	e8 d4 fe ff ff       	callq  400e5a <outDgt>

0000000000400f86 <_CDI_printf.s.outDgt_TO_printf.s.divOut_1>:
  400f86:	90                   	nop
  400f87:	c9                   	leaveq 
  400f88:	48 83 c4 08          	add    $0x8,%rsp
  400f8c:	48 81 7c 24 f8 ae 12 	cmpq   $0x4012ae,-0x8(%rsp)
  400f93:	40 00 
  400f95:	0f 84 13 03 00 00    	je     4012ae <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_1>
  400f9b:	48 81 7c 24 f8 b8 12 	cmpq   $0x4012b8,-0x8(%rsp)
  400fa2:	40 00 
  400fa4:	0f 84 0e 03 00 00    	je     4012b8 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_2>
  400faa:	48 81 7c 24 f8 c2 12 	cmpq   $0x4012c2,-0x8(%rsp)
  400fb1:	40 00 
  400fb3:	0f 84 09 03 00 00    	je     4012c2 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_3>
  400fb9:	48 81 7c 24 f8 cc 12 	cmpq   $0x4012cc,-0x8(%rsp)
  400fc0:	40 00 
  400fc2:	0f 84 04 03 00 00    	je     4012cc <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_4>
  400fc8:	48 81 7c 24 f8 43 13 	cmpq   $0x401343,-0x8(%rsp)
  400fcf:	40 00 
  400fd1:	0f 84 6c 03 00 00    	je     401343 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_5>
  400fd7:	48 81 7c 24 f8 4d 13 	cmpq   $0x40134d,-0x8(%rsp)
  400fde:	40 00 
  400fe0:	0f 84 67 03 00 00    	je     40134d <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_6>
  400fe6:	48 81 7c 24 f8 57 13 	cmpq   $0x401357,-0x8(%rsp)
  400fed:	40 00 
  400fef:	0f 84 62 03 00 00    	je     401357 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_7>
  400ff5:	48 81 7c 24 f8 8b 09 	cmpq   $0x40098b,-0x8(%rsp)
  400ffc:	40 00 
  400ffe:	0f 84 87 f9 ff ff    	je     40098b <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_1>
  401004:	48 81 7c 24 f8 bd 0a 	cmpq   $0x400abd,-0x8(%rsp)
  40100b:	40 00 
  40100d:	0f 84 aa fa ff ff    	je     400abd <_CDI_printf.s.divOut_TO_benchmark.s.cipher_main_2>
  401013:	48 c7 c6 26 10 40 00 	mov    $0x401026,%rsi
  40101a:	48 c7 c2 1d 00 00 00 	mov    $0x1d,%rdx
  401021:	e8 2d 06 00 00       	callq  401653 <_CDI_abort>

0000000000401026 <.CDI_sled_id_11>:
  401026:	70 72                	jo     40109a <tfp_printf+0x57>
  401028:	69 6e 74 66 2e 63 3a 	imul   $0x3a632e66,0x74(%rsi),%ebp
  40102f:	36 37                	ss (bad) 
  401031:	3a 30                	cmp    (%rax),%dh
  401033:	3a 70 72             	cmp    0x72(%rax),%dh
  401036:	69 6e 74 66 2e 73 20 	imul   $0x20732e66,0x74(%rsi),%ebp
  40103d:	69 64 3d 31 31 00 55 	imul   $0x48550031,0x31(%rbp,%rdi,1),%esp
  401044:	48 

0000000000401043 <tfp_printf>:
  401043:	55                   	push   %rbp
  401044:	48 89 e5             	mov    %rsp,%rbp
  401047:	48 81 ec f0 00 00 00 	sub    $0xf0,%rsp
  40104e:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
  401055:	48 89 b5 58 ff ff ff 	mov    %rsi,-0xa8(%rbp)
  40105c:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
  401063:	48 89 8d 68 ff ff ff 	mov    %rcx,-0x98(%rbp)
  40106a:	4c 89 85 70 ff ff ff 	mov    %r8,-0x90(%rbp)
  401071:	4c 89 8d 78 ff ff ff 	mov    %r9,-0x88(%rbp)
  401078:	84 c0                	test   %al,%al
  40107a:	74 20                	je     40109c <tfp_printf+0x59>
  40107c:	0f 29 45 80          	movaps %xmm0,-0x80(%rbp)
  401080:	0f 29 4d 90          	movaps %xmm1,-0x70(%rbp)
  401084:	0f 29 55 a0          	movaps %xmm2,-0x60(%rbp)
  401088:	0f 29 5d b0          	movaps %xmm3,-0x50(%rbp)
  40108c:	0f 29 65 c0          	movaps %xmm4,-0x40(%rbp)
  401090:	0f 29 6d d0          	movaps %xmm5,-0x30(%rbp)
  401094:	0f 29 75 e0          	movaps %xmm6,-0x20(%rbp)
  401098:	0f 29 7d f0          	movaps %xmm7,-0x10(%rbp)
  40109c:	c7 85 20 ff ff ff 08 	movl   $0x8,-0xe0(%rbp)
  4010a3:	00 00 00 
  4010a6:	c7 85 24 ff ff ff 30 	movl   $0x30,-0xdc(%rbp)
  4010ad:	00 00 00 
  4010b0:	48 8d 45 10          	lea    0x10(%rbp),%rax
  4010b4:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
  4010bb:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
  4010c2:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
  4010c9:	e9 f7 03 00 00       	jmpq   4014c5 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3+0x24>
  4010ce:	80 bd 4f ff ff ff 25 	cmpb   $0x25,-0xb1(%rbp)
  4010d5:	74 13                	je     4010ea <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x5>
  4010d7:	0f be 85 4f ff ff ff 	movsbl -0xb1(%rbp),%eax
  4010de:	89 c7                	mov    %eax,%edi
  4010e0:	e8 23 fc ff ff       	callq  400d08 <outchar>

00000000004010e5 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1>:
  4010e5:	e9 db 03 00 00       	jmpq   4014c5 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3+0x24>
  4010ea:	c6 85 3f ff ff ff 00 	movb   $0x0,-0xc1(%rbp)
  4010f1:	c6 85 3e ff ff ff 00 	movb   $0x0,-0xc2(%rbp)
  4010f8:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
  4010ff:	48 8d 50 01          	lea    0x1(%rax),%rdx
  401103:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
  40110a:	0f b6 00             	movzbl (%rax),%eax
  40110d:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
  401113:	80 bd 4f ff ff ff 30 	cmpb   $0x30,-0xb1(%rbp)
  40111a:	75 22                	jne    40113e <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x59>
  40111c:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
  401123:	48 8d 50 01          	lea    0x1(%rax),%rdx
  401127:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
  40112e:	0f b6 00             	movzbl (%rax),%eax
  401131:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
  401137:	c6 85 3f ff ff ff 01 	movb   $0x1,-0xc1(%rbp)
  40113e:	80 bd 4f ff ff ff 2f 	cmpb   $0x2f,-0xb1(%rbp)
  401145:	7e 6b                	jle    4011b2 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0xcd>
  401147:	80 bd 4f ff ff ff 39 	cmpb   $0x39,-0xb1(%rbp)
  40114e:	7f 62                	jg     4011b2 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0xcd>
  401150:	c6 85 3e ff ff ff 00 	movb   $0x0,-0xc2(%rbp)
  401157:	eb 47                	jmp    4011a0 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0xbb>
  401159:	0f b6 85 3e ff ff ff 	movzbl -0xc2(%rbp),%eax
  401160:	8d 14 85 00 00 00 00 	lea    0x0(,%rax,4),%edx
  401167:	0f b6 85 3e ff ff ff 	movzbl -0xc2(%rbp),%eax
  40116e:	01 d0                	add    %edx,%eax
  401170:	8d 14 00             	lea    (%rax,%rax,1),%edx
  401173:	0f b6 85 4f ff ff ff 	movzbl -0xb1(%rbp),%eax
  40117a:	01 d0                	add    %edx,%eax
  40117c:	83 e8 30             	sub    $0x30,%eax
  40117f:	88 85 3e ff ff ff    	mov    %al,-0xc2(%rbp)
  401185:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
  40118c:	48 8d 50 01          	lea    0x1(%rax),%rdx
  401190:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
  401197:	0f b6 00             	movzbl (%rax),%eax
  40119a:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
  4011a0:	80 bd 4f ff ff ff 2f 	cmpb   $0x2f,-0xb1(%rbp)
  4011a7:	7e 09                	jle    4011b2 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0xcd>
  4011a9:	80 bd 4f ff ff ff 39 	cmpb   $0x39,-0xb1(%rbp)
  4011b0:	7e a7                	jle    401159 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x74>
  4011b2:	48 c7 05 6b 0b 20 00 	movq   $0x601d30,0x200b6b(%rip)        # 601d28 <bf>
  4011b9:	30 1d 60 00 
  4011bd:	48 8b 05 64 0b 20 00 	mov    0x200b64(%rip),%rax        # 601d28 <bf>
  4011c4:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  4011cb:	c6 05 6f 0b 20 00 00 	movb   $0x0,0x200b6f(%rip)        # 601d41 <zs>
  4011d2:	0f be 85 4f ff ff ff 	movsbl -0xb1(%rbp),%eax
  4011d9:	83 f8 63             	cmp    $0x63,%eax
  4011dc:	0f 84 8a 01 00 00    	je     40136c <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_2+0x5>
  4011e2:	83 f8 63             	cmp    $0x63,%eax
  4011e5:	7f 1f                	jg     401206 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x121>
  4011e7:	83 f8 25             	cmp    $0x25,%eax
  4011ea:	0f 84 16 02 00 00    	je     401406 <_CDI_printf.s.out_TO_printf.s.tfp_printf_2+0x4e>
  4011f0:	83 f8 58             	cmp    $0x58,%eax
  4011f3:	0f 84 e8 00 00 00    	je     4012e1 <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1+0x5>
  4011f9:	85 c0                	test   %eax,%eax
  4011fb:	0f 84 ee 02 00 00    	je     4014ef <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3+0x4e>
  401201:	e9 0a 02 00 00       	jmpq   401410 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3>
  401206:	83 f8 73             	cmp    $0x73,%eax
  401209:	0f 84 ab 01 00 00    	je     4013ba <_CDI_printf.s.out_TO_printf.s.tfp_printf_2+0x2>
  40120f:	83 f8 73             	cmp    $0x73,%eax
  401212:	7f 0a                	jg     40121e <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x139>
  401214:	83 f8 64             	cmp    $0x64,%eax
  401217:	74 18                	je     401231 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x14c>
  401219:	e9 f2 01 00 00       	jmpq   401410 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3>
  40121e:	83 f8 75             	cmp    $0x75,%eax
  401221:	74 0e                	je     401231 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x14c>
  401223:	83 f8 78             	cmp    $0x78,%eax
  401226:	0f 84 b5 00 00 00    	je     4012e1 <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1+0x5>
  40122c:	e9 df 01 00 00       	jmpq   401410 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3>
  401231:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
  401237:	83 f8 2f             	cmp    $0x2f,%eax
  40123a:	77 23                	ja     40125f <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x17a>
  40123c:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
  401243:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  401249:	89 d2                	mov    %edx,%edx
  40124b:	48 01 d0             	add    %rdx,%rax
  40124e:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  401254:	83 c2 08             	add    $0x8,%edx
  401257:	89 95 20 ff ff ff    	mov    %edx,-0xe0(%rbp)
  40125d:	eb 12                	jmp    401271 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x18c>
  40125f:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
  401266:	48 8d 50 08          	lea    0x8(%rax),%rdx
  40126a:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
  401271:	8b 00                	mov    (%rax),%eax
  401273:	89 05 c3 0a 20 00    	mov    %eax,0x200ac3(%rip)        # 601d3c <num>
  401279:	80 bd 4f ff ff ff 64 	cmpb   $0x64,-0xb1(%rbp)
  401280:	75 22                	jne    4012a4 <_CDI_printf.s.out_TO_printf.s.tfp_printf_1>
  401282:	8b 05 b4 0a 20 00    	mov    0x200ab4(%rip),%eax        # 601d3c <num>
  401288:	85 c0                	test   %eax,%eax
  40128a:	79 18                	jns    4012a4 <_CDI_printf.s.out_TO_printf.s.tfp_printf_1>
  40128c:	8b 05 aa 0a 20 00    	mov    0x200aaa(%rip),%eax        # 601d3c <num>
  401292:	f7 d8                	neg    %eax
  401294:	89 05 a2 0a 20 00    	mov    %eax,0x200aa2(%rip)        # 601d3c <num>
  40129a:	bf 2d 00 00 00       	mov    $0x2d,%edi
  40129f:	e8 06 fb ff ff       	callq  400daa <out>

00000000004012a4 <_CDI_printf.s.out_TO_printf.s.tfp_printf_1>:
  4012a4:	bf 10 27 00 00       	mov    $0x2710,%edi
  4012a9:	e8 75 fc ff ff       	callq  400f23 <divOut>

00000000004012ae <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_1>:
  4012ae:	bf e8 03 00 00       	mov    $0x3e8,%edi
  4012b3:	e8 6b fc ff ff       	callq  400f23 <divOut>

00000000004012b8 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_2>:
  4012b8:	bf 64 00 00 00       	mov    $0x64,%edi
  4012bd:	e8 61 fc ff ff       	callq  400f23 <divOut>

00000000004012c2 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_3>:
  4012c2:	bf 0a 00 00 00       	mov    $0xa,%edi
  4012c7:	e8 57 fc ff ff       	callq  400f23 <divOut>

00000000004012cc <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_4>:
  4012cc:	8b 05 6a 0a 20 00    	mov    0x200a6a(%rip),%eax        # 601d3c <num>
  4012d2:	0f be c0             	movsbl %al,%eax
  4012d5:	89 c7                	mov    %eax,%edi
  4012d7:	e8 7e fb ff ff       	callq  400e5a <outDgt>

00000000004012dc <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1>:
  4012dc:	e9 30 01 00 00       	jmpq   401411 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x1>
  4012e1:	80 bd 4f ff ff ff 58 	cmpb   $0x58,-0xb1(%rbp)
  4012e8:	0f 94 c0             	sete   %al
  4012eb:	88 05 4f 0a 20 00    	mov    %al,0x200a4f(%rip)        # 601d40 <uc>
  4012f1:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
  4012f7:	83 f8 2f             	cmp    $0x2f,%eax
  4012fa:	77 23                	ja     40131f <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1+0x43>
  4012fc:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
  401303:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  401309:	89 d2                	mov    %edx,%edx
  40130b:	48 01 d0             	add    %rdx,%rax
  40130e:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  401314:	83 c2 08             	add    $0x8,%edx
  401317:	89 95 20 ff ff ff    	mov    %edx,-0xe0(%rbp)
  40131d:	eb 12                	jmp    401331 <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_1+0x55>
  40131f:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
  401326:	48 8d 50 08          	lea    0x8(%rax),%rdx
  40132a:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
  401331:	8b 00                	mov    (%rax),%eax
  401333:	89 05 03 0a 20 00    	mov    %eax,0x200a03(%rip)        # 601d3c <num>
  401339:	bf 00 10 00 00       	mov    $0x1000,%edi
  40133e:	e8 e0 fb ff ff       	callq  400f23 <divOut>

0000000000401343 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_5>:
  401343:	bf 00 01 00 00       	mov    $0x100,%edi
  401348:	e8 d6 fb ff ff       	callq  400f23 <divOut>

000000000040134d <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_6>:
  40134d:	bf 10 00 00 00       	mov    $0x10,%edi
  401352:	e8 cc fb ff ff       	callq  400f23 <divOut>

0000000000401357 <_CDI_printf.s.divOut_TO_printf.s.tfp_printf_7>:
  401357:	8b 05 df 09 20 00    	mov    0x2009df(%rip),%eax        # 601d3c <num>
  40135d:	0f be c0             	movsbl %al,%eax
  401360:	89 c7                	mov    %eax,%edi
  401362:	e8 f3 fa ff ff       	callq  400e5a <outDgt>

0000000000401367 <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_2>:
  401367:	e9 a5 00 00 00       	jmpq   401411 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x1>
  40136c:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
  401372:	83 f8 2f             	cmp    $0x2f,%eax
  401375:	77 23                	ja     40139a <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_2+0x33>
  401377:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
  40137e:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  401384:	89 d2                	mov    %edx,%edx
  401386:	48 01 d0             	add    %rdx,%rax
  401389:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  40138f:	83 c2 08             	add    $0x8,%edx
  401392:	89 95 20 ff ff ff    	mov    %edx,-0xe0(%rbp)
  401398:	eb 12                	jmp    4013ac <_CDI_printf.s.outDgt_TO_printf.s.tfp_printf_2+0x45>
  40139a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
  4013a1:	48 8d 50 08          	lea    0x8(%rax),%rdx
  4013a5:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
  4013ac:	8b 00                	mov    (%rax),%eax
  4013ae:	0f be c0             	movsbl %al,%eax
  4013b1:	89 c7                	mov    %eax,%edi
  4013b3:	e8 f2 f9 ff ff       	callq  400daa <out>

00000000004013b8 <_CDI_printf.s.out_TO_printf.s.tfp_printf_2>:
  4013b8:	eb 57                	jmp    401411 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x1>
  4013ba:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
  4013c0:	83 f8 2f             	cmp    $0x2f,%eax
  4013c3:	77 23                	ja     4013e8 <_CDI_printf.s.out_TO_printf.s.tfp_printf_2+0x30>
  4013c5:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
  4013cc:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  4013d2:	89 d2                	mov    %edx,%edx
  4013d4:	48 01 d0             	add    %rdx,%rax
  4013d7:	8b 95 20 ff ff ff    	mov    -0xe0(%rbp),%edx
  4013dd:	83 c2 08             	add    $0x8,%edx
  4013e0:	89 95 20 ff ff ff    	mov    %edx,-0xe0(%rbp)
  4013e6:	eb 12                	jmp    4013fa <_CDI_printf.s.out_TO_printf.s.tfp_printf_2+0x42>
  4013e8:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
  4013ef:	48 8d 50 08          	lea    0x8(%rax),%rdx
  4013f3:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
  4013fa:	48 8b 00             	mov    (%rax),%rax
  4013fd:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  401404:	eb 0b                	jmp    401411 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x1>
  401406:	bf 25 00 00 00       	mov    $0x25,%edi
  40140b:	e8 9a f9 ff ff       	callq  400daa <out>

0000000000401410 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3>:
  401410:	90                   	nop
  401411:	48 8b 05 10 09 20 00 	mov    0x200910(%rip),%rax        # 601d28 <bf>
  401418:	c6 00 00             	movb   $0x0,(%rax)
  40141b:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
  401422:	48 89 05 ff 08 20 00 	mov    %rax,0x2008ff(%rip)        # 601d28 <bf>
  401429:	eb 10                	jmp    40143b <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x2b>
  40142b:	0f b6 85 3e ff ff ff 	movzbl -0xc2(%rbp),%eax
  401432:	83 e8 01             	sub    $0x1,%eax
  401435:	88 85 3e ff ff ff    	mov    %al,-0xc2(%rbp)
  40143b:	48 8b 05 e6 08 20 00 	mov    0x2008e6(%rip),%rax        # 601d28 <bf>
  401442:	48 8d 50 01          	lea    0x1(%rax),%rdx
  401446:	48 89 15 db 08 20 00 	mov    %rdx,0x2008db(%rip)        # 601d28 <bf>
  40144d:	0f b6 00             	movzbl (%rax),%eax
  401450:	84 c0                	test   %al,%al
  401452:	74 27                	je     40147b <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_2>
  401454:	80 bd 3e ff ff ff 00 	cmpb   $0x0,-0xc2(%rbp)
  40145b:	7f ce                	jg     40142b <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x1b>
  40145d:	eb 1c                	jmp    40147b <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_2>
  40145f:	80 bd 3f ff ff ff 00 	cmpb   $0x0,-0xc1(%rbp)
  401466:	74 07                	je     40146f <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x5f>
  401468:	b8 30 00 00 00       	mov    $0x30,%eax
  40146d:	eb 05                	jmp    401474 <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x64>
  40146f:	b8 20 00 00 00       	mov    $0x20,%eax
  401474:	89 c7                	mov    %eax,%edi
  401476:	e8 8d f8 ff ff       	callq  400d08 <outchar>

000000000040147b <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_2>:
  40147b:	0f b6 85 3e ff ff ff 	movzbl -0xc2(%rbp),%eax
  401482:	89 c2                	mov    %eax,%edx
  401484:	83 ea 01             	sub    $0x1,%edx
  401487:	88 95 3e ff ff ff    	mov    %dl,-0xc2(%rbp)
  40148d:	84 c0                	test   %al,%al
  40148f:	7f ce                	jg     40145f <_CDI_printf.s.out_TO_printf.s.tfp_printf_3+0x4f>
  401491:	eb 0e                	jmp    4014a1 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3>
  401493:	0f be 85 4f ff ff ff 	movsbl -0xb1(%rbp),%eax
  40149a:	89 c7                	mov    %eax,%edi
  40149c:	e8 67 f8 ff ff       	callq  400d08 <outchar>

00000000004014a1 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3>:
  4014a1:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
  4014a8:	48 8d 50 01          	lea    0x1(%rax),%rdx
  4014ac:	48 89 95 40 ff ff ff 	mov    %rdx,-0xc0(%rbp)
  4014b3:	0f b6 00             	movzbl (%rax),%eax
  4014b6:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
  4014bc:	80 bd 4f ff ff ff 00 	cmpb   $0x0,-0xb1(%rbp)
  4014c3:	75 ce                	jne    401493 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_2+0x18>
  4014c5:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
  4014cc:	48 8d 50 01          	lea    0x1(%rax),%rdx
  4014d0:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
  4014d7:	0f b6 00             	movzbl (%rax),%eax
  4014da:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
  4014e0:	80 bd 4f ff ff ff 00 	cmpb   $0x0,-0xb1(%rbp)
  4014e7:	0f 85 e1 fb ff ff    	jne    4010ce <tfp_printf+0x8b>
  4014ed:	eb 01                	jmp    4014f0 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_3+0x4f>
  4014ef:	90                   	nop
  4014f0:	90                   	nop
  4014f1:	c9                   	leaveq 
  4014f2:	48 83 c4 08          	add    $0x8,%rsp
  4014f6:	48 81 7c 24 f8 15 0a 	cmpq   $0x400a15,-0x8(%rsp)
  4014fd:	40 00 
  4014ff:	0f 84 10 f5 ff ff    	je     400a15 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_1>
  401505:	48 81 7c 24 f8 47 0b 	cmpq   $0x400b47,-0x8(%rsp)
  40150c:	40 00 
  40150e:	0f 84 33 f6 ff ff    	je     400b47 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_2>
  401514:	48 81 7c 24 f8 d6 0b 	cmpq   $0x400bd6,-0x8(%rsp)
  40151b:	40 00 
  40151d:	0f 84 b3 f6 ff ff    	je     400bd6 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_3>
  401523:	48 81 7c 24 f8 12 0c 	cmpq   $0x400c12,-0x8(%rsp)
  40152a:	40 00 
  40152c:	0f 84 e0 f6 ff ff    	je     400c12 <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_4>
  401532:	48 81 7c 24 f8 4e 0c 	cmpq   $0x400c4e,-0x8(%rsp)
  401539:	40 00 
  40153b:	0f 84 0d f7 ff ff    	je     400c4e <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_5>
  401541:	48 81 7c 24 f8 8a 0c 	cmpq   $0x400c8a,-0x8(%rsp)
  401548:	40 00 
  40154a:	0f 84 3a f7 ff ff    	je     400c8a <_CDI_printf.s.tfp_printf_TO_benchmark.s.cipher_main_6>
  401550:	48 81 7c 24 f8 d7 05 	cmpq   $0x4005d7,-0x8(%rsp)
  401557:	40 00 
  401559:	0f 84 78 f0 ff ff    	je     4005d7 <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_1>
  40155f:	48 81 7c 24 f8 e6 05 	cmpq   $0x4005e6,-0x8(%rsp)
  401566:	40 00 
  401568:	0f 84 78 f0 ff ff    	je     4005e6 <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_2>
  40156e:	48 81 7c 24 f8 6d 06 	cmpq   $0x40066d,-0x8(%rsp)
  401575:	40 00 
  401577:	0f 84 f0 f0 ff ff    	je     40066d <_CDI_printf.s.tfp_printf_TO_benchmark.s.hanoi_main_3>
  40157d:	48 c7 c6 90 15 40 00 	mov    $0x401590,%rsi
  401584:	48 c7 c2 1e 00 00 00 	mov    $0x1e,%rdx
  40158b:	e8 c3 00 00 00       	callq  401653 <_CDI_abort>

0000000000401590 <.CDI_sled_id_12>:
  401590:	70 72                	jo     401604 <__libc_csu_init+0x54>
  401592:	69 6e 74 66 2e 63 3a 	imul   $0x3a632e66,0x74(%rsi),%ebp
  401599:	31 34 37             	xor    %esi,(%rdi,%rsi,1)
  40159c:	3a 30                	cmp    (%rax),%dh
  40159e:	3a 70 72             	cmp    0x72(%rax),%dh
  4015a1:	69 6e 74 66 2e 73 20 	imul   $0x20732e66,0x74(%rsi),%ebp
  4015a8:	69 64 3d 31 32 00 66 	imul   $0x90660032,0x31(%rbp,%rdi,1),%esp
  4015af:	90 

00000000004015b0 <__libc_csu_init>:
  4015b0:	41 57                	push   %r15
  4015b2:	41 56                	push   %r14
  4015b4:	41 89 ff             	mov    %edi,%r15d
  4015b7:	41 55                	push   %r13
  4015b9:	41 54                	push   %r12
  4015bb:	4c 8d 25 fe 04 20 00 	lea    0x2004fe(%rip),%r12        # 601ac0 <__frame_dummy_init_array_entry>
  4015c2:	55                   	push   %rbp
  4015c3:	48 8d 2d fe 04 20 00 	lea    0x2004fe(%rip),%rbp        # 601ac8 <__init_array_end>
  4015ca:	53                   	push   %rbx
  4015cb:	49 89 f6             	mov    %rsi,%r14
  4015ce:	49 89 d5             	mov    %rdx,%r13
  4015d1:	4c 29 e5             	sub    %r12,%rbp
  4015d4:	48 83 ec 08          	sub    $0x8,%rsp
  4015d8:	48 c1 fd 03          	sar    $0x3,%rbp
  4015dc:	e8 4f ed ff ff       	callq  400330 <_init>
  4015e1:	48 85 ed             	test   %rbp,%rbp
  4015e4:	74 20                	je     401606 <__libc_csu_init+0x56>
  4015e6:	31 db                	xor    %ebx,%ebx
  4015e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4015ef:	00 
  4015f0:	4c 89 ea             	mov    %r13,%rdx
  4015f3:	4c 89 f6             	mov    %r14,%rsi
  4015f6:	44 89 ff             	mov    %r15d,%edi
  4015f9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4015fd:	48 83 c3 01          	add    $0x1,%rbx
  401601:	48 39 eb             	cmp    %rbp,%rbx
  401604:	75 ea                	jne    4015f0 <__libc_csu_init+0x40>
  401606:	48 83 c4 08          	add    $0x8,%rsp
  40160a:	5b                   	pop    %rbx
  40160b:	5d                   	pop    %rbp
  40160c:	41 5c                	pop    %r12
  40160e:	41 5d                	pop    %r13
  401610:	41 5e                	pop    %r14
  401612:	41 5f                	pop    %r15
  401614:	c3                   	retq   
  401615:	90                   	nop
  401616:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40161d:	00 00 00 

0000000000401620 <__libc_csu_fini>:
  401620:	f3 c3                	repz retq 

0000000000401622 <.generic_msg>:
  401622:	63 64 69 3a          	movslq 0x3a(%rcx,%rbp,2),%esp
  401626:	20 75 6e             	and    %dh,0x6e(%rbp)
  401629:	73 61                	jae    40168c <_CDI_abort+0x39>
  40162b:	66 65 20 6d 6f       	data16 and %ch,%gs:0x6f(%rbp)
  401630:	76 65                	jbe    401697 <_CDI_abort+0x44>
  401632:	6d                   	insl   (%dx),%es:(%rdi)
  401633:	65 6e                	outsb  %gs:(%rsi),(%dx)
  401635:	74 2c                	je     401663 <_CDI_abort+0x10>
  401637:	20 61 62             	and    %ah,0x62(%rcx)
  40163a:	6f                   	outsl  %ds:(%rsi),(%dx)
  40163b:	72 74                	jb     4016b1 <_CDI_abort+0x5e>
  40163d:	69 6e 67 2e 2e 2e 0a 	imul   $0xa2e2e2e,0x67(%rsi),%ebp
	...

0000000000401645 <.debug_msg>:
  401645:	63 64 69 3a          	movslq 0x3a(%rcx,%rbp,2),%esp
  401649:	20 73 6c             	and    %dh,0x6c(%rbx)
  40164c:	65 64 3a 20          	gs cmp %fs:(%rax),%ah
	...

0000000000401651 <.newline_char>:
  401651:	0a 00                	or     (%rax),%al

0000000000401653 <_CDI_abort>:
  401653:	55                   	push   %rbp
  401654:	48 89 e5             	mov    %rsp,%rbp
  401657:	56                   	push   %rsi
  401658:	52                   	push   %rdx
  401659:	48 c7 c6 22 16 40 00 	mov    $0x401622,%rsi
  401660:	48 c7 c2 23 00 00 00 	mov    $0x23,%rdx
  401667:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  40166e:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  401675:	0f 05                	syscall 
  401677:	5a                   	pop    %rdx
  401678:	48 83 fa 00          	cmp    $0x0,%rdx
  40167c:	74 4f                	je     4016cd <.abort>
  40167e:	52                   	push   %rdx
  40167f:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  401686:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  40168d:	48 c7 c2 0c 00 00 00 	mov    $0xc,%rdx
  401694:	48 c7 c6 45 16 40 00 	mov    $0x401645,%rsi
  40169b:	0f 05                	syscall 
  40169d:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4016a4:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  4016ab:	5a                   	pop    %rdx
  4016ac:	5e                   	pop    %rsi
  4016ad:	0f 05                	syscall 
  4016af:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4016b6:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  4016bd:	48 c7 c2 01 00 00 00 	mov    $0x1,%rdx
  4016c4:	48 c7 c6 51 16 40 00 	mov    $0x401651,%rsi
  4016cb:	0f 05                	syscall 

00000000004016cd <.abort>:
  4016cd:	48 c7 c0 27 00 00 00 	mov    $0x27,%rax
  4016d4:	0f 05                	syscall 
  4016d6:	48 89 c7             	mov    %rax,%rdi
  4016d9:	48 c7 c0 3e 00 00 00 	mov    $0x3e,%rax
  4016e0:	48 c7 c6 0b 00 00 00 	mov    $0xb,%rsi
  4016e7:	0f 05                	syscall 

Disassembly of section .fini:

00000000004016ec <_fini>:
  4016ec:	48 83 ec 08          	sub    $0x8,%rsp
  4016f0:	48 83 c4 08          	add    $0x8,%rsp
  4016f4:	c3                   	retq   

Disassembly of section .rodata:

00000000004016f8 <_IO_stdin_used>:
  4016f8:	01 00                	add    %eax,(%rax)
  4016fa:	02 00                	add    (%rax),%al
  4016fc:	00 00                	add    %al,(%rax)
  4016fe:	00 00                	add    %al,(%rax)
  401700:	54                   	push   %rsp
  401701:	6f                   	outsl  %ds:(%rsi),(%dx)
  401702:	77 65                	ja     401769 <_IO_stdin_used+0x71>
  401704:	72 73                	jb     401779 <_IO_stdin_used+0x81>
  401706:	20 6f 66             	and    %ch,0x66(%rdi)
  401709:	20 48 61             	and    %cl,0x61(%rax)
  40170c:	6e                   	outsb  %ds:(%rsi),(%dx)
  40170d:	6f                   	outsl  %ds:(%rsi),(%dx)
  40170e:	69 20 50 75 7a 7a    	imul   $0x7a7a7550,(%rax),%esp
  401714:	6c                   	insb   (%dx),%es:(%rdi)
  401715:	65 20 54 65 73       	and    %dl,%gs:0x73(%rbp,%riz,2)
  40171a:	74 20                	je     40173c <_IO_stdin_used+0x44>
  40171c:	50                   	push   %rax
  40171d:	72 6f                	jb     40178e <_IO_stdin_used+0x96>
  40171f:	67 72 61             	addr32 jb 401783 <_IO_stdin_used+0x8b>
  401722:	6d                   	insl   (%dx),%es:(%rdi)
  401723:	0a 00                	or     (%rax),%al
  401725:	44 69 73 6b 73 20 20 	imul   $0x20202073,0x6b(%rbx),%r14d
  40172c:	20 
  40172d:	20 20                	and    %ah,(%rax)
  40172f:	4d 6f                	rex.WRB outsl %ds:(%rsi),(%dx)
  401731:	76 65                	jbe    401798 <_IO_stdin_used+0xa0>
  401733:	73 0a                	jae    40173f <_IO_stdin_used+0x47>
  401735:	00 25 33 64 20 20    	add    %ah,0x20206433(%rip)        # 20607b6e <_end+0x20005e16>
  40173b:	25 30 34 58 25       	and    $0x25583430,%eax
  401740:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  401743:	0a 00                	or     (%rax),%al
  401745:	54                   	push   %rsp
  401746:	45                   	rex.RB
  401747:	41 20 43 69          	and    %al,0x69(%r11)
  40174b:	70 68                	jo     4017b5 <_IO_stdin_used+0xbd>
  40174d:	65 72 20             	gs jb  401770 <_IO_stdin_used+0x78>
  401750:	72 65                	jb     4017b7 <_IO_stdin_used+0xbf>
  401752:	73 75                	jae    4017c9 <_IO_stdin_used+0xd1>
  401754:	6c                   	insb   (%dx),%es:(%rdi)
  401755:	74 73                	je     4017ca <_IO_stdin_used+0xd2>
  401757:	3a 0a                	cmp    (%rdx),%cl
  401759:	00 00                	add    %al,(%rax)
  40175b:	00 00                	add    %al,(%rax)
  40175d:	00 00                	add    %al,(%rax)
  40175f:	00 20                	add    %ah,(%rax)
  401761:	20 70 6c             	and    %dh,0x6c(%rax)
  401764:	61                   	(bad)  
  401765:	69 6e 74 65 78 74 3a 	imul   $0x3a747865,0x74(%rsi),%ebp
  40176c:	20 20                	and    %ah,(%rax)
  40176e:	30 78 25             	xor    %bh,0x25(%rax)
  401771:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  401774:	25 30 34 58 20       	and    $0x20583430,%eax
  401779:	30 78 25             	xor    %bh,0x25(%rax)
  40177c:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  40177f:	25 30 34 58 0a       	and    $0xa583430,%eax
  401784:	00 00                	add    %al,(%rax)
  401786:	00 00                	add    %al,(%rax)
  401788:	20 20                	and    %ah,(%rax)
  40178a:	63 69 70             	movslq 0x70(%rcx),%ebp
  40178d:	68 65 72 74 65       	pushq  $0x65747265
  401792:	78 74                	js     401808 <__GNU_EH_FRAME_HDR+0x30>
  401794:	3a 20                	cmp    (%rax),%ah
  401796:	30 78 25             	xor    %bh,0x25(%rax)
  401799:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  40179c:	25 30 34 58 20       	and    $0x20583430,%eax
  4017a1:	30 78 25             	xor    %bh,0x25(%rax)
  4017a4:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  4017a7:	25 30 34 58 0a       	and    $0xa583430,%eax
  4017ac:	00 00                	add    %al,(%rax)
  4017ae:	00 00                	add    %al,(%rax)
  4017b0:	20 20                	and    %ah,(%rax)
  4017b2:	6e                   	outsb  %ds:(%rsi),(%dx)
  4017b3:	65 77 70             	gs ja  401826 <__GNU_EH_FRAME_HDR+0x4e>
  4017b6:	6c                   	insb   (%dx),%es:(%rdi)
  4017b7:	61                   	(bad)  
  4017b8:	69 6e 3a 20 20 20 30 	imul   $0x30202020,0x3a(%rsi),%ebp
  4017bf:	78 25                	js     4017e6 <__GNU_EH_FRAME_HDR+0xe>
  4017c1:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  4017c4:	25 30 34 58 20       	and    $0x20583430,%eax
  4017c9:	30 78 25             	xor    %bh,0x25(%rax)
  4017cc:	30 34 58             	xor    %dh,(%rax,%rbx,2)
  4017cf:	25 30 34 58 0a       	and    $0xa583430,%eax
	...

Disassembly of section .eh_frame_hdr:

00000000004017d8 <__GNU_EH_FRAME_HDR>:
  4017d8:	01 1b                	add    %ebx,(%rbx)
  4017da:	03 3b                	add    (%rbx),%edi
  4017dc:	8c 00                	mov    %es,(%rax)
  4017de:	00 00                	add    %al,(%rax)
  4017e0:	10 00                	adc    %al,(%rax)
  4017e2:	00 00                	add    %al,(%rax)
  4017e4:	78 eb                	js     4017d1 <_IO_stdin_used+0xd9>
  4017e6:	ff                   	(bad)  
  4017e7:	ff                   	(bad)  
  4017e8:	d8 00                	fadds  (%rax)
  4017ea:	00 00                	add    %al,(%rax)
  4017ec:	a8 eb                	test   $0xeb,%al
  4017ee:	ff                   	(bad)  
  4017ef:	ff a8 00 00 00 9e    	ljmp   *-0x62000000(%rax)
  4017f5:	ec                   	in     (%dx),%al
  4017f6:	ff                   	(bad)  
  4017f7:	ff 00                	incl   (%rax)
  4017f9:	01 00                	add    %eax,(%rax)
  4017fb:	00 e1                	add    %ah,%cl
  4017fd:	ed                   	in     (%dx),%eax
  4017fe:	ff                   	(bad)  
  4017ff:	ff 20                	jmpq   *(%rax)
  401801:	01 00                	add    %eax,(%rax)
  401803:	00 0d ef ff ff 40    	add    %cl,0x40ffffef(%rip)        # 414017f8 <_end+0x40dffaa0>
  401809:	01 00                	add    %eax,(%rax)
  40180b:	00 48 f0             	add    %cl,-0x10(%rax)
  40180e:	ff                   	(bad)  
  40180f:	ff 60 01             	jmpq   *0x1(%rax)
  401812:	00 00                	add    %al,(%rax)
  401814:	83 f1 ff             	xor    $0xffffffff,%ecx
  401817:	ff 80 01 00 00 1b    	incl   0x1b000001(%rax)
  40181d:	f5                   	cmc    
  40181e:	ff                   	(bad)  
  40181f:	ff a0 01 00 00 30    	jmpq   *0x30000001(%rax)
  401825:	f5                   	cmc    
  401826:	ff                   	(bad)  
  401827:	ff c0                	inc    %eax
  401829:	01 00                	add    %eax,(%rax)
  40182b:	00 d2                	add    %dl,%dl
  40182d:	f5                   	cmc    
  40182e:	ff                   	(bad)  
  40182f:	ff e0                	jmpq   *%rax
  401831:	01 00                	add    %eax,(%rax)
  401833:	00 82 f6 ff ff 00    	add    %al,0xfffff6(%rdx)
  401839:	02 00                	add    (%rax),%al
  40183b:	00 4b f7             	add    %cl,-0x9(%rbx)
  40183e:	ff                   	(bad)  
  40183f:	ff 20                	jmpq   *(%rax)
  401841:	02 00                	add    (%rax),%al
  401843:	00 6b f8             	add    %ch,-0x8(%rbx)
  401846:	ff                   	(bad)  
  401847:	ff 40 02             	incl   0x2(%rax)
  40184a:	00 00                	add    %al,(%rax)
  40184c:	d8 fd                	fdivr  %st(5),%st
  40184e:	ff                   	(bad)  
  40184f:	ff 60 02             	jmpq   *0x2(%rax)
  401852:	00 00                	add    %al,(%rax)
  401854:	48 fe                	rex.W (bad) 
  401856:	ff                   	(bad)  
  401857:	ff a8 02 00 00 7b    	ljmp   *0x7b000002(%rax)
  40185d:	fe                   	(bad)  
  40185e:	ff                   	(bad)  
  40185f:	ff c8                	dec    %eax
  401861:	02 00                	add    (%rax),%al
	...

Disassembly of section .eh_frame:

0000000000401868 <__FRAME_END__-0x230>:
  401868:	14 00                	adc    $0x0,%al
  40186a:	00 00                	add    %al,(%rax)
  40186c:	00 00                	add    %al,(%rax)
  40186e:	00 00                	add    %al,(%rax)
  401870:	01 7a 52             	add    %edi,0x52(%rdx)
  401873:	00 01                	add    %al,(%rcx)
  401875:	78 10                	js     401887 <__GNU_EH_FRAME_HDR+0xaf>
  401877:	01 1b                	add    %ebx,(%rbx)
  401879:	0c 07                	or     $0x7,%al
  40187b:	08 90 01 07 10 14    	or     %dl,0x14100701(%rax)
  401881:	00 00                	add    %al,(%rax)
  401883:	00 1c 00             	add    %bl,(%rax,%rax,1)
  401886:	00 00                	add    %al,(%rax)
  401888:	f8                   	clc    
  401889:	ea                   	(bad)  
  40188a:	ff                   	(bad)  
  40188b:	ff 2a                	ljmp   *(%rdx)
	...
  401895:	00 00                	add    %al,(%rax)
  401897:	00 14 00             	add    %dl,(%rax,%rax,1)
  40189a:	00 00                	add    %al,(%rax)
  40189c:	00 00                	add    %al,(%rax)
  40189e:	00 00                	add    %al,(%rax)
  4018a0:	01 7a 52             	add    %edi,0x52(%rdx)
  4018a3:	00 01                	add    %al,(%rcx)
  4018a5:	78 10                	js     4018b7 <__GNU_EH_FRAME_HDR+0xdf>
  4018a7:	01 1b                	add    %ebx,(%rbx)
  4018a9:	0c 07                	or     $0x7,%al
  4018ab:	08 90 01 00 00 24    	or     %dl,0x24000001(%rax)
  4018b1:	00 00                	add    %al,(%rax)
  4018b3:	00 1c 00             	add    %bl,(%rax,%rax,1)
  4018b6:	00 00                	add    %al,(%rax)
  4018b8:	98                   	cwtl   
  4018b9:	ea                   	(bad)  
  4018ba:	ff                   	(bad)  
  4018bb:	ff 20                	jmpq   *(%rax)
  4018bd:	00 00                	add    %al,(%rax)
  4018bf:	00 00                	add    %al,(%rax)
  4018c1:	0e                   	(bad)  
  4018c2:	10 46 0e             	adc    %al,0xe(%rsi)
  4018c5:	18 4a 0f             	sbb    %cl,0xf(%rdx)
  4018c8:	0b 77 08             	or     0x8(%rdi),%esi
  4018cb:	80 00 3f             	addb   $0x3f,(%rax)
  4018ce:	1a 3b                	sbb    (%rbx),%bh
  4018d0:	2a 33                	sub    (%rbx),%dh
  4018d2:	24 22                	and    $0x22,%al
  4018d4:	00 00                	add    %al,(%rax)
  4018d6:	00 00                	add    %al,(%rax)
  4018d8:	1c 00                	sbb    $0x0,%al
  4018da:	00 00                	add    %al,(%rax)
  4018dc:	44 00 00             	add    %r8b,(%rax)
  4018df:	00 96 eb ff ff 43    	add    %dl,0x43ffffeb(%rsi)
  4018e5:	01 00                	add    %eax,(%rax)
  4018e7:	00 00                	add    %al,(%rax)
  4018e9:	41 0e                	rex.B (bad) 
  4018eb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4018f1:	02 b8 0c 07 08 00    	add    0x8070c(%rax),%bh
  4018f7:	00 1c 00             	add    %bl,(%rax,%rax,1)
  4018fa:	00 00                	add    %al,(%rax)
  4018fc:	64 00 00             	add    %al,%fs:(%rax)
  4018ff:	00 b9 ec ff ff 2c    	add    %bh,0x2cffffec(%rcx)
  401905:	01 00                	add    %eax,(%rax)
  401907:	00 00                	add    %al,(%rax)
  401909:	41 0e                	rex.B (bad) 
  40190b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401911:	02 c2                	add    %dl,%al
  401913:	0c 07                	or     $0x7,%al
  401915:	08 00                	or     %al,(%rax)
  401917:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40191a:	00 00                	add    %al,(%rax)
  40191c:	84 00                	test   %al,(%rax)
  40191e:	00 00                	add    %al,(%rax)
  401920:	c5 ed ff             	(bad)  
  401923:	ff                   	(bad)  
  401924:	3b 01                	cmp    (%rcx),%eax
  401926:	00 00                	add    %al,(%rax)
  401928:	00 41 0e             	add    %al,0xe(%rcx)
  40192b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401931:	02 e0                	add    %al,%ah
  401933:	0c 07                	or     $0x7,%al
  401935:	08 00                	or     %al,(%rax)
  401937:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40193a:	00 00                	add    %al,(%rax)
  40193c:	a4                   	movsb  %ds:(%rsi),%es:(%rdi)
  40193d:	00 00                	add    %al,(%rax)
  40193f:	00 e0                	add    %ah,%al
  401941:	ee                   	out    %al,(%dx)
  401942:	ff                   	(bad)  
  401943:	ff                   	(bad)  
  401944:	3b 01                	cmp    (%rcx),%eax
  401946:	00 00                	add    %al,(%rax)
  401948:	00 41 0e             	add    %al,0xe(%rcx)
  40194b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401951:	02 e0                	add    %al,%ah
  401953:	0c 07                	or     $0x7,%al
  401955:	08 00                	or     %al,(%rax)
  401957:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40195a:	00 00                	add    %al,(%rax)
  40195c:	c4                   	(bad)  
  40195d:	00 00                	add    %al,(%rax)
  40195f:	00 fb                	add    %bh,%bl
  401961:	ef                   	out    %eax,(%dx)
  401962:	ff                   	(bad)  
  401963:	ff 98 03 00 00 00    	lcall  *0x3(%rax)
  401969:	41 0e                	rex.B (bad) 
  40196b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401971:	03 31                	add    (%rcx),%esi
  401973:	03 0c 07             	add    (%rdi,%rax,1),%ecx
  401976:	08 00                	or     %al,(%rax)
  401978:	1c 00                	sbb    $0x0,%al
  40197a:	00 00                	add    %al,(%rax)
  40197c:	e4 00                	in     $0x0,%al
  40197e:	00 00                	add    %al,(%rax)
  401980:	73 f3                	jae    401975 <__GNU_EH_FRAME_HDR+0x19d>
  401982:	ff                   	(bad)  
  401983:	ff 15 00 00 00 00    	callq  *0x0(%rip)        # 401989 <__GNU_EH_FRAME_HDR+0x1b1>
  401989:	41 0e                	rex.B (bad) 
  40198b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401991:	50                   	push   %rax
  401992:	0c 07                	or     $0x7,%al
  401994:	08 00                	or     %al,(%rax)
  401996:	00 00                	add    %al,(%rax)
  401998:	1c 00                	sbb    $0x0,%al
  40199a:	00 00                	add    %al,(%rax)
  40199c:	04 01                	add    $0x1,%al
  40199e:	00 00                	add    %al,(%rax)
  4019a0:	68 f3 ff ff a2       	pushq  $0xffffffffa2fffff3
  4019a5:	00 00                	add    %al,(%rax)
  4019a7:	00 00                	add    %al,(%rax)
  4019a9:	41 0e                	rex.B (bad) 
  4019ab:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4019b1:	5f                   	pop    %rdi
  4019b2:	0c 07                	or     $0x7,%al
  4019b4:	08 00                	or     %al,(%rax)
  4019b6:	00 00                	add    %al,(%rax)
  4019b8:	1c 00                	sbb    $0x0,%al
  4019ba:	00 00                	add    %al,(%rax)
  4019bc:	24 01                	and    $0x1,%al
  4019be:	00 00                	add    %al,(%rax)
  4019c0:	ea                   	(bad)  
  4019c1:	f3 ff                	repz (bad) 
  4019c3:	ff b0 00 00 00 00    	pushq  0x0(%rax)
  4019c9:	41 0e                	rex.B (bad) 
  4019cb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4019d1:	5f                   	pop    %rdi
  4019d2:	0c 07                	or     $0x7,%al
  4019d4:	08 00                	or     %al,(%rax)
  4019d6:	00 00                	add    %al,(%rax)
  4019d8:	1c 00                	sbb    $0x0,%al
  4019da:	00 00                	add    %al,(%rax)
  4019dc:	44 01 00             	add    %r8d,(%rax)
  4019df:	00 7a f4             	add    %bh,-0xc(%rdx)
  4019e2:	ff                   	(bad)  
  4019e3:	ff c9                	dec    %ecx
  4019e5:	00 00                	add    %al,(%rax)
  4019e7:	00 00                	add    %al,(%rax)
  4019e9:	41 0e                	rex.B (bad) 
  4019eb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4019f1:	02 46 0c             	add    0xc(%rsi),%al
  4019f4:	07                   	(bad)  
  4019f5:	08 00                	or     %al,(%rax)
  4019f7:	00 1c 00             	add    %bl,(%rax,%rax,1)
  4019fa:	00 00                	add    %al,(%rax)
  4019fc:	64 01 00             	add    %eax,%fs:(%rax)
  4019ff:	00 23                	add    %ah,(%rbx)
  401a01:	f5                   	cmc    
  401a02:	ff                   	(bad)  
  401a03:	ff 20                	jmpq   *(%rax)
  401a05:	01 00                	add    %eax,(%rax)
  401a07:	00 00                	add    %al,(%rax)
  401a09:	41 0e                	rex.B (bad) 
  401a0b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401a11:	02 61 0c             	add    0xc(%rcx),%ah
  401a14:	07                   	(bad)  
  401a15:	08 00                	or     %al,(%rax)
  401a17:	00 1c 00             	add    %bl,(%rax,%rax,1)
  401a1a:	00 00                	add    %al,(%rax)
  401a1c:	84 01                	test   %al,(%rcx)
  401a1e:	00 00                	add    %al,(%rax)
  401a20:	23 f6                	and    %esi,%esi
  401a22:	ff                   	(bad)  
  401a23:	ff 6b 05             	ljmp   *0x5(%rbx)
  401a26:	00 00                	add    %al,(%rax)
  401a28:	00 41 0e             	add    %al,0xe(%rcx)
  401a2b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401a31:	03 ab 04 0c 07 08    	add    0x8070c04(%rbx),%ebp
  401a37:	00 44 00 00          	add    %al,0x0(%rax,%rax,1)
  401a3b:	00 a4 01 00 00 70 fb 	add    %ah,-0x4900000(%rcx,%rax,1)
  401a42:	ff                   	(bad)  
  401a43:	ff 65 00             	jmpq   *0x0(%rbp)
  401a46:	00 00                	add    %al,(%rax)
  401a48:	00 42 0e             	add    %al,0xe(%rdx)
  401a4b:	10 8f 02 42 0e 18    	adc    %cl,0x180e4202(%rdi)
  401a51:	8e 03                	mov    (%rbx),%es
  401a53:	45 0e                	rex.RB (bad) 
  401a55:	20 8d 04 42 0e 28    	and    %cl,0x280e4204(%rbp)
  401a5b:	8c 05 48 0e 30 86    	mov    %es,-0x79cff1b8(%rip)        # ffffffff867028a9 <_end+0xffffffff86100b51>
  401a61:	06                   	(bad)  
  401a62:	48 0e                	rex.W (bad) 
  401a64:	38 83 07 4d 0e 40    	cmp    %al,0x400e4d07(%rbx)
  401a6a:	72 0e                	jb     401a7a <__GNU_EH_FRAME_HDR+0x2a2>
  401a6c:	38 41 0e             	cmp    %al,0xe(%rcx)
  401a6f:	30 41 0e             	xor    %al,0xe(%rcx)
  401a72:	28 42 0e             	sub    %al,0xe(%rdx)
  401a75:	20 42 0e             	and    %al,0xe(%rdx)
  401a78:	18 42 0e             	sbb    %al,0xe(%rdx)
  401a7b:	10 42 0e             	adc    %al,0xe(%rdx)
  401a7e:	08 00                	or     %al,(%rax)
  401a80:	14 00                	adc    $0x0,%al
  401a82:	00 00                	add    %al,(%rax)
  401a84:	ec                   	in     (%dx),%al
  401a85:	01 00                	add    %eax,(%rax)
  401a87:	00 98 fb ff ff 02    	add    %bl,0x2fffffb(%rax)
	...

0000000000401a98 <__FRAME_END__>:
	...
  401aa0:	1c 00                	sbb    $0x0,%al
  401aa2:	00 00                	add    %al,(%rax)
  401aa4:	0c 02                	or     $0x2,%al
  401aa6:	00 00                	add    %al,(%rax)
  401aa8:	ab                   	stos   %eax,%es:(%rdi)
  401aa9:	fb                   	sti    
  401aaa:	ff                   	(bad)  
  401aab:	ff 96 00 00 00 00    	callq  *0x0(%rsi)
  401ab1:	41 0e                	rex.B (bad) 
  401ab3:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  401ab9:	00 00                	add    %al,(%rax)
  401abb:	00 00                	add    %al,(%rax)
  401abd:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000601ac0 <__frame_dummy_init_array_entry>:
  601ac0:	50                   	push   %rax
  601ac1:	04 40                	add    $0x40,%al
  601ac3:	00 00                	add    %al,(%rax)
  601ac5:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000601ac8 <__do_global_dtors_aux_fini_array_entry>:
  601ac8:	30 04 40             	xor    %al,(%rax,%rax,2)
  601acb:	00 00                	add    %al,(%rax)
  601acd:	00 00                	add    %al,(%rax)
	...

Disassembly of section .jcr:

0000000000601ad0 <__JCR_END__>:
	...

Disassembly of section .dynamic:

0000000000601ad8 <_DYNAMIC>:
  601ad8:	01 00                	add    %eax,(%rax)
  601ada:	00 00                	add    %al,(%rax)
  601adc:	00 00                	add    %al,(%rax)
  601ade:	00 00                	add    %al,(%rax)
  601ae0:	01 00                	add    %eax,(%rax)
  601ae2:	00 00                	add    %al,(%rax)
  601ae4:	00 00                	add    %al,(%rax)
  601ae6:	00 00                	add    %al,(%rax)
  601ae8:	0c 00                	or     $0x0,%al
  601aea:	00 00                	add    %al,(%rax)
  601aec:	00 00                	add    %al,(%rax)
  601aee:	00 00                	add    %al,(%rax)
  601af0:	30 03                	xor    %al,(%rbx)
  601af2:	40 00 00             	add    %al,(%rax)
  601af5:	00 00                	add    %al,(%rax)
  601af7:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 601afd <_DYNAMIC+0x25>
  601afd:	00 00                	add    %al,(%rax)
  601aff:	00 ec                	add    %ch,%ah
  601b01:	16                   	(bad)  
  601b02:	40 00 00             	add    %al,(%rax)
  601b05:	00 00                	add    %al,(%rax)
  601b07:	00 19                	add    %bl,(%rcx)
  601b09:	00 00                	add    %al,(%rax)
  601b0b:	00 00                	add    %al,(%rax)
  601b0d:	00 00                	add    %al,(%rax)
  601b0f:	00 c0                	add    %al,%al
  601b11:	1a 60 00             	sbb    0x0(%rax),%ah
  601b14:	00 00                	add    %al,(%rax)
  601b16:	00 00                	add    %al,(%rax)
  601b18:	1b 00                	sbb    (%rax),%eax
  601b1a:	00 00                	add    %al,(%rax)
  601b1c:	00 00                	add    %al,(%rax)
  601b1e:	00 00                	add    %al,(%rax)
  601b20:	08 00                	or     %al,(%rax)
  601b22:	00 00                	add    %al,(%rax)
  601b24:	00 00                	add    %al,(%rax)
  601b26:	00 00                	add    %al,(%rax)
  601b28:	1a 00                	sbb    (%rax),%al
  601b2a:	00 00                	add    %al,(%rax)
  601b2c:	00 00                	add    %al,(%rax)
  601b2e:	00 00                	add    %al,(%rax)
  601b30:	c8 1a 60 00          	enterq $0x601a,$0x0
  601b34:	00 00                	add    %al,(%rax)
  601b36:	00 00                	add    %al,(%rax)
  601b38:	1c 00                	sbb    $0x0,%al
  601b3a:	00 00                	add    %al,(%rax)
  601b3c:	00 00                	add    %al,(%rax)
  601b3e:	00 00                	add    %al,(%rax)
  601b40:	08 00                	or     %al,(%rax)
  601b42:	00 00                	add    %al,(%rax)
  601b44:	00 00                	add    %al,(%rax)
  601b46:	00 00                	add    %al,(%rax)
  601b48:	04 00                	add    $0x0,%al
  601b4a:	00 00                	add    %al,(%rax)
  601b4c:	00 00                	add    %al,(%rax)
  601b4e:	00 00                	add    %al,(%rax)
  601b50:	40 02 40 00          	add    0x0(%rax),%al
  601b54:	00 00                	add    %al,(%rax)
  601b56:	00 00                	add    %al,(%rax)
  601b58:	05 00 00 00 00       	add    $0x0,%eax
  601b5d:	00 00                	add    %al,(%rax)
  601b5f:	00 a0 02 40 00 00    	add    %ah,0x4002(%rax)
  601b65:	00 00                	add    %al,(%rax)
  601b67:	00 06                	add    %al,(%rsi)
  601b69:	00 00                	add    %al,(%rax)
  601b6b:	00 00                	add    %al,(%rax)
  601b6d:	00 00                	add    %al,(%rax)
  601b6f:	00 58 02             	add    %bl,0x2(%rax)
  601b72:	40 00 00             	add    %al,(%rax)
  601b75:	00 00                	add    %al,(%rax)
  601b77:	00 0a                	add    %cl,(%rdx)
  601b79:	00 00                	add    %al,(%rax)
  601b7b:	00 00                	add    %al,(%rax)
  601b7d:	00 00                	add    %al,(%rax)
  601b7f:	00 38                	add    %bh,(%rax)
  601b81:	00 00                	add    %al,(%rax)
  601b83:	00 00                	add    %al,(%rax)
  601b85:	00 00                	add    %al,(%rax)
  601b87:	00 0b                	add    %cl,(%rbx)
  601b89:	00 00                	add    %al,(%rax)
  601b8b:	00 00                	add    %al,(%rax)
  601b8d:	00 00                	add    %al,(%rax)
  601b8f:	00 18                	add    %bl,(%rax)
  601b91:	00 00                	add    %al,(%rax)
  601b93:	00 00                	add    %al,(%rax)
  601b95:	00 00                	add    %al,(%rax)
  601b97:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 601b9d <_DYNAMIC+0xc5>
	...
  601ba5:	00 00                	add    %al,(%rax)
  601ba7:	00 03                	add    %al,(%rbx)
  601ba9:	00 00                	add    %al,(%rax)
  601bab:	00 00                	add    %al,(%rax)
  601bad:	00 00                	add    %al,(%rax)
  601baf:	00 b0 1c 60 00 00    	add    %dh,0x601c(%rax)
  601bb5:	00 00                	add    %al,(%rax)
  601bb7:	00 02                	add    %al,(%rdx)
  601bb9:	00 00                	add    %al,(%rax)
  601bbb:	00 00                	add    %al,(%rax)
  601bbd:	00 00                	add    %al,(%rax)
  601bbf:	00 18                	add    %bl,(%rax)
  601bc1:	00 00                	add    %al,(%rax)
  601bc3:	00 00                	add    %al,(%rax)
  601bc5:	00 00                	add    %al,(%rax)
  601bc7:	00 14 00             	add    %dl,(%rax,%rax,1)
  601bca:	00 00                	add    %al,(%rax)
  601bcc:	00 00                	add    %al,(%rax)
  601bce:	00 00                	add    %al,(%rax)
  601bd0:	07                   	(bad)  
  601bd1:	00 00                	add    %al,(%rax)
  601bd3:	00 00                	add    %al,(%rax)
  601bd5:	00 00                	add    %al,(%rax)
  601bd7:	00 17                	add    %dl,(%rdi)
  601bd9:	00 00                	add    %al,(%rax)
  601bdb:	00 00                	add    %al,(%rax)
  601bdd:	00 00                	add    %al,(%rax)
  601bdf:	00 18                	add    %bl,(%rax)
  601be1:	03 40 00             	add    0x0(%rax),%eax
  601be4:	00 00                	add    %al,(%rax)
  601be6:	00 00                	add    %al,(%rax)
  601be8:	07                   	(bad)  
	...
  601bf1:	03 40 00             	add    0x0(%rax),%eax
  601bf4:	00 00                	add    %al,(%rax)
  601bf6:	00 00                	add    %al,(%rax)
  601bf8:	08 00                	or     %al,(%rax)
  601bfa:	00 00                	add    %al,(%rax)
  601bfc:	00 00                	add    %al,(%rax)
  601bfe:	00 00                	add    %al,(%rax)
  601c00:	18 00                	sbb    %al,(%rax)
  601c02:	00 00                	add    %al,(%rax)
  601c04:	00 00                	add    %al,(%rax)
  601c06:	00 00                	add    %al,(%rax)
  601c08:	09 00                	or     %eax,(%rax)
  601c0a:	00 00                	add    %al,(%rax)
  601c0c:	00 00                	add    %al,(%rax)
  601c0e:	00 00                	add    %al,(%rax)
  601c10:	18 00                	sbb    %al,(%rax)
  601c12:	00 00                	add    %al,(%rax)
  601c14:	00 00                	add    %al,(%rax)
  601c16:	00 00                	add    %al,(%rax)
  601c18:	fe                   	(bad)  
  601c19:	ff                   	(bad)  
  601c1a:	ff 6f 00             	ljmp   *0x0(%rdi)
  601c1d:	00 00                	add    %al,(%rax)
  601c1f:	00 e0                	add    %ah,%al
  601c21:	02 40 00             	add    0x0(%rax),%al
  601c24:	00 00                	add    %al,(%rax)
  601c26:	00 00                	add    %al,(%rax)
  601c28:	ff                   	(bad)  
  601c29:	ff                   	(bad)  
  601c2a:	ff 6f 00             	ljmp   *0x0(%rdi)
  601c2d:	00 00                	add    %al,(%rax)
  601c2f:	00 01                	add    %al,(%rcx)
  601c31:	00 00                	add    %al,(%rax)
  601c33:	00 00                	add    %al,(%rax)
  601c35:	00 00                	add    %al,(%rax)
  601c37:	00 f0                	add    %dh,%al
  601c39:	ff                   	(bad)  
  601c3a:	ff 6f 00             	ljmp   *0x0(%rdi)
  601c3d:	00 00                	add    %al,(%rax)
  601c3f:	00 d8                	add    %bl,%al
  601c41:	02 40 00             	add    0x0(%rax),%al
	...

Disassembly of section .got:

0000000000601ca8 <.got>:
	...

Disassembly of section .got.plt:

0000000000601cb0 <_GLOBAL_OFFSET_TABLE_>:
  601cb0:	d8 1a                	fcomps (%rdx)
  601cb2:	60                   	(bad)  
	...
  601cc7:	00 66 03             	add    %ah,0x3(%rsi)
  601cca:	40 00 00             	add    %al,(%rax)
  601ccd:	00 00                	add    %al,(%rax)
	...

Disassembly of section .data:

0000000000601cd0 <__data_start>:
	...

0000000000601cd8 <__dso_handle>:
	...

0000000000601ce0 <keytext>:
  601ce0:	d2 a5 63 15 09 bb    	shlb   %cl,-0x44f6ea9d(%rbp)
  601ce6:	92                   	xchg   %eax,%edx
  601ce7:	12 4b e5             	adc    -0x1b(%rbx),%cl
  601cea:	0d 2c e4 ae 58       	or     $0x58aee42c,%eax
  601cef:	33 0e                	xor    (%rsi),%ecx

0000000000601cf0 <plaintext>:
  601cf0:	0e                   	(bad)  
  601cf1:	85 a2 2d 4d 66 d9    	test   %esp,-0x2699b2d3(%rdx)
	...

0000000000601cf8 <cipherref>:
  601cf8:	64 c8 e2 9f a4       	fs enterq $0x9fe2,$0xa4
  601cfd:	4d da d7             	rex.WRB fcmovbe %st(7),%st

Disassembly of section .bss:

0000000000601d00 <__bss_start>:
	...

0000000000601d10 <num>:
	...

0000000000601d20 <count>:
	...

0000000000601d28 <bf>:
	...

0000000000601d30 <buf>:
	...

0000000000601d3c <num>:
  601d3c:	00 00                	add    %al,(%rax)
	...

0000000000601d40 <uc>:
	...

0000000000601d41 <zs>:
  601d41:	00 00                	add    %al,(%rax)
  601d43:	00 00                	add    %al,(%rax)
  601d45:	00 00                	add    %al,(%rax)
	...

0000000000601d48 <newplain>:
	...

0000000000601d50 <ciphertext>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 47 4e             	sub    %al,0x4e(%rdi)
   8:	55                   	push   %rbp
   9:	29 20                	sub    %esp,(%rax)
   b:	36 2e 31 2e          	ss xor %ebp,%cs:(%rsi)
   f:	30 00                	xor    %al,(%rax)

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    $0x0,%al
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 00                	or     %al,(%rax)
   c:	00 00                	add    %al,(%rax)
   e:	00 00                	add    %al,(%rax)
  10:	76 04                	jbe    16 <.debug_msg_len+0xa>
  12:	40 00 00             	add    %al,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	00 92 08 00 00 00    	add    %dl,0x8(%rdx)
	...
  2d:	00 00                	add    %al,(%rax)
  2f:	00 2c 00             	add    %ch,(%rax,%rax,1)
  32:	00 00                	add    %al,(%rax)
  34:	02 00                	add    (%rax),%al
  36:	90                   	nop
  37:	03 00                	add    (%rax),%eax
  39:	00 08                	add    %cl,(%rax)
  3b:	00 00                	add    %al,(%rax)
  3d:	00 00                	add    %al,(%rax)
  3f:	00 08                	add    %cl,(%rax)
  41:	0d 40 00 00 00       	or     $0x40,%eax
  46:	00 00                	add    %al,(%rax)
  48:	a6                   	cmpsb  %es:(%rdi),%ds:(%rsi)
  49:	08 00                	or     %al,(%rax)
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	8c 03                	mov    %es,(%rbx)
   2:	00 00                	add    %al,(%rax)
   4:	04 00                	add    $0x0,%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 01                	or     %al,(%rcx)
   c:	cd 00                	int    $0x0
   e:	00 00                	add    %al,(%rax)
  10:	0c 9f                	or     $0x9f,%al
  12:	00 00                	add    %al,(%rax)
  14:	00 42 00             	add    %al,0x0(%rdx)
  17:	00 00                	add    %al,(%rax)
  19:	76 04                	jbe    1f <.CDI_sled_id_12_len+0x1>
  1b:	40 00 00             	add    %al,(%rax)
  1e:	00 00                	add    %al,(%rax)
  20:	00 92 08 00 00 00    	add    %dl,0x8(%rdx)
  26:	00 00                	add    %al,(%rax)
  28:	00 00                	add    %al,(%rax)
  2a:	00 00                	add    %al,(%rax)
  2c:	00 02                	add    %al,(%rdx)
  2e:	08 07                	or     %al,(%rdi)
  30:	c4                   	(bad)  
  31:	00 00                	add    %al,(%rax)
  33:	00 02                	add    %al,(%rdx)
  35:	04 07                	add    $0x7,%al
  37:	92                   	xchg   %eax,%edx
  38:	00 00                	add    %al,(%rax)
  3a:	00 03                	add    %al,(%rbx)
  3c:	34 00                	xor    $0x0,%al
  3e:	00 00                	add    %al,(%rax)
  40:	04 50                	add    $0x50,%al
  42:	00 00                	add    %al,(%rax)
  44:	00 50 00             	add    %dl,0x0(%rax)
  47:	00 00                	add    %al,(%rax)
  49:	05 2d 00 00 00       	add    $0x2d,%eax
  4e:	03 00                	add    (%rax),%eax
  50:	06                   	(bad)  
  51:	04 05                	add    $0x5,%al
  53:	69 6e 74 00 07 6e 75 	imul   $0x756e0700,0x74(%rsi),%ebp
  5a:	6d                   	insl   (%dx),%es:(%rdi)
  5b:	00 01                	add    %al,(%rcx)
  5d:	07                   	(bad)  
  5e:	40 00 00             	add    %al,(%rax)
  61:	00 09                	add    %cl,(%rcx)
  63:	03 10                	add    (%rax),%edx
  65:	1d 60 00 00 00       	sbb    $0x60,%eax
  6a:	00 00                	add    %al,(%rax)
  6c:	08 17                	or     %dl,(%rdi)
  6e:	00 00                	add    %al,(%rax)
  70:	00 01                	add    %al,(%rcx)
  72:	08 81 00 00 00 09    	or     %al,0x9000000(%rcx)
  78:	03 20                	add    (%rax),%esp
  7a:	1d 60 00 00 00       	sbb    $0x60,%eax
  7f:	00 00                	add    %al,(%rax)
  81:	02 08                	add    (%rax),%cl
  83:	05 fb 00 00 00       	add    $0xfb,%eax
  88:	04 34                	add    $0x34,%al
  8a:	00 00                	add    %al,(%rax)
  8c:	00 98 00 00 00 05    	add    %bl,0x5000000(%rax)
  92:	2d 00 00 00 03       	sub    $0x3000000,%eax
  97:	00 09                	add    %cl,(%rcx)
  99:	04 01                	add    $0x1,%al
  9b:	00 00                	add    %al,(%rax)
  9d:	01 5e 88             	add    %ebx,-0x78(%rsi)
  a0:	00 00                	add    %al,(%rax)
  a2:	00 09                	add    %cl,(%rcx)
  a4:	03 e0                	add    %eax,%esp
  a6:	1c 60                	sbb    $0x60,%al
  a8:	00 00                	add    %al,(%rax)
  aa:	00 00                	add    %al,(%rax)
  ac:	00 04 34             	add    %al,(%rsp,%rsi,1)
  af:	00 00                	add    %al,(%rax)
  b1:	00 bd 00 00 00 05    	add    %bh,0x5000000(%rbp)
  b7:	2d 00 00 00 01       	sub    $0x1000000,%eax
  bc:	00 09                	add    %cl,(%rcx)
  be:	2f                   	(bad)  
  bf:	00 00                	add    %al,(%rax)
  c1:	00 01                	add    %al,(%rcx)
  c3:	5f                   	pop    %rdi
  c4:	ad                   	lods   %ds:(%rsi),%eax
  c5:	00 00                	add    %al,(%rax)
  c7:	00 09                	add    %cl,(%rcx)
  c9:	03 f0                	add    %eax,%esi
  cb:	1c 60                	sbb    $0x60,%al
  cd:	00 00                	add    %al,(%rax)
  cf:	00 00                	add    %al,(%rax)
  d1:	00 09                	add    %cl,(%rcx)
  d3:	79 00                	jns    d5 <.CDI_sled_id_5_len+0xb2>
  d5:	00 00                	add    %al,(%rax)
  d7:	01 60 ad             	add    %esp,-0x53(%rax)
  da:	00 00                	add    %al,(%rax)
  dc:	00 09                	add    %cl,(%rcx)
  de:	03 f8                	add    %eax,%edi
  e0:	1c 60                	sbb    $0x60,%al
  e2:	00 00                	add    %al,(%rax)
  e4:	00 00                	add    %al,(%rax)
  e6:	00 09                	add    %cl,(%rcx)
  e8:	00 00                	add    %al,(%rax)
  ea:	00 00                	add    %al,(%rax)
  ec:	01 61 ad             	add    %esp,-0x53(%rcx)
  ef:	00 00                	add    %al,(%rax)
  f1:	00 09                	add    %cl,(%rcx)
  f3:	03 50 1d             	add    0x1d(%rax),%edx
  f6:	60                   	(bad)  
  f7:	00 00                	add    %al,(%rax)
  f9:	00 00                	add    %al,(%rax)
  fb:	00 09                	add    %cl,(%rcx)
  fd:	b0 00                	mov    $0x0,%al
  ff:	00 00                	add    %al,(%rax)
 101:	01 62 ad             	add    %esp,-0x53(%rdx)
 104:	00 00                	add    %al,(%rax)
 106:	00 09                	add    %cl,(%rcx)
 108:	03 48 1d             	add    0x1d(%rax),%ecx
 10b:	60                   	(bad)  
 10c:	00 00                	add    %al,(%rax)
 10e:	00 00                	add    %al,(%rax)
 110:	00 0a                	add    %cl,(%rdx)
 112:	bf 00 00 00 01       	mov    $0x1000000,%edi
 117:	84 50 00             	test   %dl,0x0(%rax)
 11a:	00 00                	add    %al,(%rax)
 11c:	f3 0c 40             	repz or $0x40,%al
 11f:	00 00                	add    %al,(%rax)
 121:	00 00                	add    %al,(%rax)
 123:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 129 <.CDI_sled_id_5_len+0x106>
 129:	00 00                	add    %al,(%rax)
 12b:	00 01                	add    %al,(%rcx)
 12d:	9c                   	pushfq 
 12e:	0b 0b                	or     (%rbx),%ecx
 130:	00 00                	add    %al,(%rax)
 132:	00 01                	add    %al,(%rcx)
 134:	66 50                	push   %ax
 136:	00 00                	add    %al,(%rax)
 138:	00 5b 09             	add    %bl,0x9(%rbx)
 13b:	40 00 00             	add    %al,(%rax)
 13e:	00 00                	add    %al,(%rax)
 140:	00 98 03 00 00 00    	add    %bl,0x3(%rax)
 146:	00 00                	add    %al,(%rax)
 148:	00 01                	add    %al,(%rcx)
 14a:	9c                   	pushfq 
 14b:	5e                   	pop    %rsi
 14c:	01 00                	add    %eax,(%rax)
 14e:	00 08                	add    %cl,(%rax)
 150:	23 00                	and    (%rax),%eax
 152:	00 00                	add    %al,(%rax)
 154:	01 68 89             	add    %ebp,-0x77(%rax)
 157:	01 00                	add    %eax,(%rax)
 159:	00 02                	add    %al,(%rdx)
 15b:	91                   	xchg   %eax,%ecx
 15c:	68 00 0c 73 01       	pushq  $0x1730c00
 161:	00 00                	add    %al,(%rax)
 163:	0d 79 01 00 00       	or     $0x179,%eax
 168:	0d 79 01 00 00       	or     $0x179,%eax
 16d:	0d 84 01 00 00       	or     $0x184,%eax
 172:	00 0e                	add    %cl,(%rsi)
 174:	08 34 00             	or     %dh,(%rax,%rax,1)
 177:	00 00                	add    %al,(%rax)
 179:	03 73 01             	add    0x1(%rbx),%esi
 17c:	00 00                	add    %al,(%rax)
 17e:	0e                   	(bad)  
 17f:	08 3b                	or     %bh,(%rbx)
 181:	00 00                	add    %al,(%rax)
 183:	00 03                	add    %al,(%rbx)
 185:	7e 01                	jle    188 <.CDI_sled_id_5_len+0x165>
 187:	00 00                	add    %al,(%rax)
 189:	0e                   	(bad)  
 18a:	08 5e 01             	or     %bl,0x1(%rsi)
 18d:	00 00                	add    %al,(%rax)
 18f:	0f 83 00 00 00 01    	jae    1000195 <_end+0x9fe43d>
 195:	4d 20 08             	rex.WRB and %r9b,(%r8)
 198:	40 00 00             	add    %al,(%rax)
 19b:	00 00                	add    %al,(%rax)
 19d:	00 3b                	add    %bh,(%rbx)
 19f:	01 00                	add    %eax,(%rax)
 1a1:	00 00                	add    %al,(%rax)
 1a3:	00 00                	add    %al,(%rax)
 1a5:	00 01                	add    %al,(%rcx)
 1a7:	9c                   	pushfq 
 1a8:	49 02 00             	rex.WB add (%r8),%al
 1ab:	00 10                	add    %dl,(%rax)
 1ad:	69 6e 00 01 4d 79 01 	imul   $0x1794d01,0x0(%rsi),%ebp
 1b4:	00 00                	add    %al,(%rax)
 1b6:	03 91 b8 7f 10 6f    	add    0x6f107fb8(%rcx),%edx
 1bc:	75 74                	jne    232 <.CDI_sled_id_5_len+0x20f>
 1be:	00 01                	add    %al,(%rcx)
 1c0:	4e 79 01             	rex.WRX jns 1c4 <.CDI_sled_id_5_len+0x1a1>
 1c3:	00 00                	add    %al,(%rax)
 1c5:	03 91 b0 7f 10 6b    	add    0x6b107fb0(%rcx),%edx
 1cb:	65 79 00             	gs jns 1ce <.CDI_sled_id_5_len+0x1ab>
 1ce:	01 4f 84             	add    %ecx,-0x7c(%rdi)
 1d1:	01 00                	add    %eax,(%rax)
 1d3:	00 03                	add    %al,(%rbx)
 1d5:	91                   	xchg   %eax,%ecx
 1d6:	a8 7f                	test   $0x7f,%al
 1d8:	07                   	(bad)  
 1d9:	79 00                	jns    1db <.CDI_sled_id_5_len+0x1b8>
 1db:	01 51 34             	add    %edx,0x34(%rcx)
 1de:	00 00                	add    %al,(%rax)
 1e0:	00 02                	add    %al,(%rdx)
 1e2:	91                   	xchg   %eax,%ecx
 1e3:	6c                   	insb   (%dx),%es:(%rdi)
 1e4:	07                   	(bad)  
 1e5:	7a 00                	jp     1e7 <.CDI_sled_id_5_len+0x1c4>
 1e7:	01 51 34             	add    %edx,0x34(%rcx)
 1ea:	00 00                	add    %al,(%rax)
 1ec:	00 02                	add    %al,(%rdx)
 1ee:	91                   	xchg   %eax,%ecx
 1ef:	68 07 73 75 6d       	pushq  $0x6d757307
 1f4:	00 01                	add    %al,(%rcx)
 1f6:	51                   	push   %rcx
 1f7:	34 00                	xor    $0x0,%al
 1f9:	00 00                	add    %al,(%rax)
 1fb:	02 91 64 08 1d 00    	add    0x1d0864(%rcx),%dl
 201:	00 00                	add    %al,(%rax)
 203:	01 51 34             	add    %edx,0x34(%rcx)
 206:	00 00                	add    %al,(%rax)
 208:	00 02                	add    %al,(%rdx)
 20a:	91                   	xchg   %eax,%ecx
 20b:	5c                   	pop    %rsp
 20c:	07                   	(bad)  
 20d:	61                   	(bad)  
 20e:	00 01                	add    %al,(%rcx)
 210:	52                   	push   %rdx
 211:	34 00                	xor    $0x0,%al
 213:	00 00                	add    %al,(%rax)
 215:	02 91 58 07 62 00    	add    0x620758(%rcx),%dl
 21b:	01 52 34             	add    %edx,0x34(%rdx)
 21e:	00 00                	add    %al,(%rax)
 220:	00 02                	add    %al,(%rdx)
 222:	91                   	xchg   %eax,%ecx
 223:	54                   	push   %rsp
 224:	07                   	(bad)  
 225:	63 00                	movslq (%rax),%eax
 227:	01 52 34             	add    %edx,0x34(%rdx)
 22a:	00 00                	add    %al,(%rax)
 22c:	00 02                	add    %al,(%rdx)
 22e:	91                   	xchg   %eax,%ecx
 22f:	50                   	push   %rax
 230:	07                   	(bad)  
 231:	64 00 01             	add    %al,%fs:(%rcx)
 234:	52                   	push   %rdx
 235:	34 00                	xor    $0x0,%al
 237:	00 00                	add    %al,(%rax)
 239:	02 91 4c 07 6e 00    	add    0x6e074c(%rcx),%dl
 23f:	01 52 34             	add    %edx,0x34(%rdx)
 242:	00 00                	add    %al,(%rax)
 244:	00 02                	add    %al,(%rdx)
 246:	91                   	xchg   %eax,%ecx
 247:	60                   	(bad)  
 248:	00 0f                	add    %cl,(%rdi)
 24a:	39 00                	cmp    %eax,(%rax)
 24c:	00 00                	add    %al,(%rax)
 24e:	01 3c e5 06 40 00 00 	add    %edi,0x4006(,%riz,8)
 255:	00 00                	add    %al,(%rax)
 257:	00 3b                	add    %bh,(%rbx)
 259:	01 00                	add    %eax,(%rax)
 25b:	00 00                	add    %al,(%rax)
 25d:	00 00                	add    %al,(%rax)
 25f:	00 01                	add    %al,(%rcx)
 261:	9c                   	pushfq 
 262:	03 03                	add    (%rbx),%eax
 264:	00 00                	add    %al,(%rax)
 266:	10 69 6e             	adc    %ch,0x6e(%rcx)
 269:	00 01                	add    %al,(%rcx)
 26b:	3c 79                	cmp    $0x79,%al
 26d:	01 00                	add    %eax,(%rax)
 26f:	00 03                	add    %al,(%rbx)
 271:	91                   	xchg   %eax,%ecx
 272:	b8 7f 10 6f 75       	mov    $0x756f107f,%eax
 277:	74 00                	je     279 <.CDI_sled_id_5_len+0x256>
 279:	01 3d 79 01 00 00    	add    %edi,0x179(%rip)        # 3f8 <.CDI_sled_id_5_len+0x3d5>
 27f:	03 91 b0 7f 10 6b    	add    0x6b107fb0(%rcx),%edx
 285:	65 79 00             	gs jns 288 <.CDI_sled_id_5_len+0x265>
 288:	01 3e                	add    %edi,(%rsi)
 28a:	84 01                	test   %al,(%rcx)
 28c:	00 00                	add    %al,(%rax)
 28e:	03 91 a8 7f 07 79    	add    0x79077fa8(%rcx),%edx
 294:	00 01                	add    %al,(%rcx)
 296:	40 34 00             	xor    $0x0,%al
 299:	00 00                	add    %al,(%rax)
 29b:	02 91 6c 07 7a 00    	add    0x7a076c(%rcx),%dl
 2a1:	01 40 34             	add    %eax,0x34(%rax)
 2a4:	00 00                	add    %al,(%rax)
 2a6:	00 02                	add    %al,(%rdx)
 2a8:	91                   	xchg   %eax,%ecx
 2a9:	68 07 73 75 6d       	pushq  $0x6d757307
 2ae:	00 01                	add    %al,(%rcx)
 2b0:	40 34 00             	xor    $0x0,%al
 2b3:	00 00                	add    %al,(%rax)
 2b5:	02 91 64 08 1d 00    	add    0x1d0864(%rcx),%dl
 2bb:	00 00                	add    %al,(%rax)
 2bd:	01 40 34             	add    %eax,0x34(%rax)
 2c0:	00 00                	add    %al,(%rax)
 2c2:	00 02                	add    %al,(%rdx)
 2c4:	91                   	xchg   %eax,%ecx
 2c5:	5c                   	pop    %rsp
 2c6:	07                   	(bad)  
 2c7:	61                   	(bad)  
 2c8:	00 01                	add    %al,(%rcx)
 2ca:	41 34 00             	rex.B xor $0x0,%al
 2cd:	00 00                	add    %al,(%rax)
 2cf:	02 91 58 07 62 00    	add    0x620758(%rcx),%dl
 2d5:	01 41 34             	add    %eax,0x34(%rcx)
 2d8:	00 00                	add    %al,(%rax)
 2da:	00 02                	add    %al,(%rdx)
 2dc:	91                   	xchg   %eax,%ecx
 2dd:	54                   	push   %rsp
 2de:	07                   	(bad)  
 2df:	63 00                	movslq (%rax),%eax
 2e1:	01 41 34             	add    %eax,0x34(%rcx)
 2e4:	00 00                	add    %al,(%rax)
 2e6:	00 02                	add    %al,(%rdx)
 2e8:	91                   	xchg   %eax,%ecx
 2e9:	50                   	push   %rax
 2ea:	07                   	(bad)  
 2eb:	64 00 01             	add    %al,%fs:(%rcx)
 2ee:	41 34 00             	rex.B xor $0x0,%al
 2f1:	00 00                	add    %al,(%rax)
 2f3:	02 91 4c 07 6e 00    	add    0x6e074c(%rcx),%dl
 2f9:	01 41 34             	add    %eax,0x34(%rcx)
 2fc:	00 00                	add    %al,(%rax)
 2fe:	00 02                	add    %al,(%rdx)
 300:	91                   	xchg   %eax,%ecx
 301:	60                   	(bad)  
 302:	00 0b                	add    %cl,(%rbx)
 304:	b9 00 00 00 01       	mov    $0x1000000,%ecx
 309:	1d 50 00 00 00       	sbb    $0x50,%eax
 30e:	b9 05 40 00 00       	mov    $0x4005,%ecx
 313:	00 00                	add    %al,(%rax)
 315:	00 2c 01             	add    %ch,(%rcx,%rax,1)
 318:	00 00                	add    %al,(%rax)
 31a:	00 00                	add    %al,(%rax)
 31c:	00 00                	add    %al,(%rax)
 31e:	01 9c 41 03 00 00 08 	add    %ebx,0x8000003(%rcx,%rax,2)
 325:	ab                   	stos   %eax,%es:(%rdi)
 326:	00 00                	add    %al,(%rax)
 328:	00 01                	add    %al,(%rcx)
 32a:	1f                   	(bad)  
 32b:	50                   	push   %rax
 32c:	00 00                	add    %al,(%rax)
 32e:	00 02                	add    %al,(%rdx)
 330:	91                   	xchg   %eax,%ecx
 331:	6c                   	insb   (%dx),%es:(%rdi)
 332:	08 8c 00 00 00 01 1f 	or     %cl,0x1f010000(%rax,%rax,1)
 339:	50                   	push   %rax
 33a:	00 00                	add    %al,(%rax)
 33c:	00 02                	add    %al,(%rdx)
 33e:	91                   	xchg   %eax,%ecx
 33f:	68 00 11 6d 6f       	pushq  $0x6f6d1100
 344:	76 00                	jbe    346 <.CDI_sled_id_5_len+0x323>
 346:	01 0b                	add    %ecx,(%rbx)
 348:	50                   	push   %rax
 349:	00 00                	add    %al,(%rax)
 34b:	00 76 04             	add    %dh,0x4(%rsi)
 34e:	40 00 00             	add    %al,(%rax)
 351:	00 00                	add    %al,(%rax)
 353:	00 43 01             	add    %al,0x1(%rbx)
 356:	00 00                	add    %al,(%rax)
 358:	00 00                	add    %al,(%rax)
 35a:	00 00                	add    %al,(%rax)
 35c:	01 9c 10 6e 00 01 0b 	add    %ebx,0xb01006e(%rax,%rdx,1)
 363:	50                   	push   %rax
 364:	00 00                	add    %al,(%rax)
 366:	00 02                	add    %al,(%rdx)
 368:	91                   	xchg   %eax,%ecx
 369:	5c                   	pop    %rsp
 36a:	10 66 00             	adc    %ah,0x0(%rsi)
 36d:	01 0b                	add    %ecx,(%rbx)
 36f:	50                   	push   %rax
 370:	00 00                	add    %al,(%rax)
 372:	00 02                	add    %al,(%rdx)
 374:	91                   	xchg   %eax,%ecx
 375:	58                   	pop    %rax
 376:	10 74 00 01          	adc    %dh,0x1(%rax,%rax,1)
 37a:	0b 50 00             	or     0x0(%rax),%edx
 37d:	00 00                	add    %al,(%rax)
 37f:	02 91 54 07 6f 00    	add    0x6f0754(%rcx),%dl
 385:	01 0c 50             	add    %ecx,(%rax,%rdx,2)
 388:	00 00                	add    %al,(%rax)
 38a:	00 02                	add    %al,(%rdx)
 38c:	91                   	xchg   %eax,%ecx
 38d:	6c                   	insb   (%dx),%es:(%rdi)
 38e:	00 00                	add    %al,(%rax)
 390:	16                   	(bad)  
 391:	02 00                	add    (%rax),%al
 393:	00 04 00             	add    %al,(%rax,%rax,1)
 396:	00 01                	add    %al,(%rcx)
 398:	00 00                	add    %al,(%rax)
 39a:	08 01                	or     %al,(%rcx)
 39c:	cd 00                	int    $0x0
 39e:	00 00                	add    %al,(%rax)
 3a0:	0c 0c                	or     $0xc,%al
 3a2:	01 00                	add    %eax,(%rax)
 3a4:	00 42 00             	add    %al,0x0(%rdx)
 3a7:	00 00                	add    %al,(%rax)
 3a9:	08 0d 40 00 00 00    	or     %cl,0x40(%rip)        # 3ef <.CDI_sled_id_5_len+0x3cc>
 3af:	00 00                	add    %al,(%rax)
 3b1:	a6                   	cmpsb  %es:(%rdi),%ds:(%rsi)
 3b2:	08 00                	or     %al,(%rax)
 3b4:	00 00                	add    %al,(%rax)
 3b6:	00 00                	add    %al,(%rax)
 3b8:	00 dc                	add    %bl,%ah
 3ba:	00 00                	add    %al,(%rax)
 3bc:	00 02                	add    %al,(%rdx)
 3be:	44 01 00             	add    %r8d,(%rax)
 3c1:	00 03                	add    %al,(%rbx)
 3c3:	28 03                	sub    %al,(%rbx)
 3c5:	08 07                	or     %al,(%rdi)
 3c7:	c4                   	(bad)  
 3c8:	00 00                	add    %al,(%rax)
 3ca:	00 03                	add    %al,(%rbx)
 3cc:	04 07                	add    $0x7,%al
 3ce:	92                   	xchg   %eax,%edx
 3cf:	00 00                	add    %al,(%rax)
 3d1:	00 04 4b             	add    %al,(%rbx,%rcx,2)
 3d4:	01 00                	add    %eax,(%rax)
 3d6:	00 03                	add    %al,(%rbx)
 3d8:	63 2d 00 00 00 05    	movslq 0x5000000(%rip),%ebp        # 50003de <_end+0x49fe686>
 3de:	62                   	(bad)  
 3df:	66 00 02             	data16 add %al,(%rdx)
 3e2:	2b 61 00             	sub    0x0(%rcx),%esp
 3e5:	00 00                	add    %al,(%rax)
 3e7:	09 03                	or     %eax,(%rbx)
 3e9:	28 1d 60 00 00 00    	sub    %bl,0x60(%rip)        # 44f <.CDI_sled_id_5_len+0x42c>
 3ef:	00 00                	add    %al,(%rax)
 3f1:	06                   	(bad)  
 3f2:	08 67 00             	or     %ah,0x0(%rdi)
 3f5:	00 00                	add    %al,(%rax)
 3f7:	03 01                	add    (%rcx),%eax
 3f9:	06                   	(bad)  
 3fa:	31 01                	xor    %eax,(%rcx)
 3fc:	00 00                	add    %al,(%rax)
 3fe:	07                   	(bad)  
 3ff:	67 00 00             	add    %al,(%eax)
 402:	00 7e 00             	add    %bh,0x0(%rsi)
 405:	00 00                	add    %al,(%rax)
 407:	08 34 00             	or     %dh,(%rax,%rax,1)
 40a:	00 00                	add    %al,(%rax)
 40c:	0b 00                	or     (%rax),%eax
 40e:	05 62 75 66 00       	add    $0x667562,%eax
 413:	02 2c 6e             	add    (%rsi,%rbp,2),%ch
 416:	00 00                	add    %al,(%rax)
 418:	00 09                	add    %cl,(%rcx)
 41a:	03 30                	add    (%rax),%esi
 41c:	1d 60 00 00 00       	sbb    $0x60,%eax
 421:	00 00                	add    %al,(%rax)
 423:	05 6e 75 6d 00       	add    $0x6d756e,%eax
 428:	02 2d 3b 00 00 00    	add    0x3b(%rip),%ch        # 469 <.CDI_sled_id_5_len+0x446>
 42e:	09 03                	or     %eax,(%rbx)
 430:	3c 1d                	cmp    $0x1d,%al
 432:	60                   	(bad)  
 433:	00 00                	add    %al,(%rax)
 435:	00 00                	add    %al,(%rax)
 437:	00 05 75 63 00 02    	add    %al,0x2006375(%rip)        # 20067b2 <_end+0x1a04a5a>
 43d:	2e 67 00 00          	add    %al,%cs:(%eax)
 441:	00 09                	add    %cl,(%rcx)
 443:	03 40 1d             	add    0x1d(%rax),%eax
 446:	60                   	(bad)  
 447:	00 00                	add    %al,(%rax)
 449:	00 00                	add    %al,(%rax)
 44b:	00 05 7a 73 00 02    	add    %al,0x200737a(%rip)        # 20077cb <_end+0x1a05a73>
 451:	2f                   	(bad)  
 452:	67 00 00             	add    %al,(%eax)
 455:	00 09                	add    %cl,(%rcx)
 457:	03 41 1d             	add    0x1d(%rcx),%eax
 45a:	60                   	(bad)  
 45b:	00 00                	add    %al,(%rax)
 45d:	00 00                	add    %al,(%rax)
 45f:	00 09                	add    %cl,(%rcx)
 461:	15 01 00 00 02       	adc    $0x2000001,%eax
 466:	45                   	rex.RB
 467:	43 10 40 00          	rex.XB adc %al,0x0(%r8)
 46b:	00 00                	add    %al,(%rax)
 46d:	00 00                	add    %al,(%rax)
 46f:	6b 05 00 00 00 00 00 	imul   $0x0,0x0(%rip),%eax        # 476 <.CDI_sled_id_5_len+0x453>
 476:	00 01                	add    %al,(%rcx)
 478:	9c                   	pushfq 
 479:	5c                   	pop    %rsp
 47a:	01 00                	add    %eax,(%rax)
 47c:	00 0a                	add    %cl,(%rdx)
 47e:	66 6d                	insw   (%dx),%es:(%rdi)
 480:	74 00                	je     482 <.CDI_sled_id_5_len+0x45f>
 482:	02 45 61             	add    0x61(%rbp),%al
 485:	00 00                	add    %al,(%rax)
 487:	00 03                	add    %al,(%rbx)
 489:	91                   	xchg   %eax,%ecx
 48a:	88 7e 0b             	mov    %bh,0xb(%rsi)
 48d:	05 76 61 00 02       	add    $0x2006176,%eax
 492:	47                   	rex.RXB
 493:	42 00 00             	rex.X add %al,(%rax)
 496:	00 03                	add    %al,(%rbx)
 498:	91                   	xchg   %eax,%ecx
 499:	90                   	nop
 49a:	7e 05                	jle    4a1 <.CDI_sled_id_5_len+0x47e>
 49c:	63 68 00             	movslq 0x0(%rax),%ebp
 49f:	02 48 67             	add    0x67(%rax),%cl
 4a2:	00 00                	add    %al,(%rax)
 4a4:	00 03                	add    %al,(%rbx)
 4a6:	91                   	xchg   %eax,%ecx
 4a7:	bf 7e 05 70 00       	mov    $0x70057e,%edi
 4ac:	02 49 61             	add    0x61(%rcx),%cl
 4af:	00 00                	add    %al,(%rax)
 4b1:	00 03                	add    %al,(%rbx)
 4b3:	91                   	xchg   %eax,%ecx
 4b4:	b0 7e                	mov    $0x7e,%al
 4b6:	0c 53                	or     $0x53,%al
 4b8:	01 00                	add    %eax,(%rax)
 4ba:	00 02                	add    %al,(%rdx)
 4bc:	91                   	xchg   %eax,%ecx
 4bd:	f0 14 40             	lock adc $0x40,%al
 4c0:	00 00                	add    %al,(%rax)
 4c2:	00 00                	add    %al,(%rax)
 4c4:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 4ca <.CDI_sled_id_5_len+0x4a7>
 4ca:	5a                   	pop    %rdx
 4cb:	01 00                	add    %eax,(%rax)
 4cd:	00 05 6c 7a 00 02    	add    %al,0x2007a6c(%rip)        # 2007f3f <_end+0x1a061e7>
 4d3:	52                   	push   %rdx
 4d4:	67 00 00             	add    %al,(%eax)
 4d7:	00 03                	add    %al,(%rbx)
 4d9:	91                   	xchg   %eax,%ecx
 4da:	af                   	scas   %es:(%rdi),%eax
 4db:	7e 05                	jle    4e2 <.CDI_sled_id_5_len+0x4bf>
 4dd:	77 00                	ja     4df <.CDI_sled_id_5_len+0x4bc>
 4df:	02 53 67             	add    0x67(%rbx),%dl
 4e2:	00 00                	add    %al,(%rax)
 4e4:	00 03                	add    %al,(%rbx)
 4e6:	91                   	xchg   %eax,%ecx
 4e7:	ae                   	scas   %es:(%rdi),%al
 4e8:	7e 00                	jle    4ea <.CDI_sled_id_5_len+0x4c7>
 4ea:	0b 00                	or     (%rax),%eax
 4ec:	0e                   	(bad)  
 4ed:	3d 01 00 00 02       	cmp    $0x2000001,%eax
 4f2:	3a 23                	cmp    (%rbx),%ah
 4f4:	0f 40 00             	cmovo  (%rax),%eax
 4f7:	00 00                	add    %al,(%rax)
 4f9:	00 00                	add    %al,(%rax)
 4fb:	20 01                	and    %al,(%rcx)
 4fd:	00 00                	add    %al,(%rax)
 4ff:	00 00                	add    %al,(%rax)
 501:	00 00                	add    %al,(%rax)
 503:	01 9c 96 01 00 00 0a 	add    %ebx,0xa000001(%rsi,%rdx,4)
 50a:	64 69 76 00 02 3a 3b 	imul   $0x3b3a02,%fs:0x0(%rsi),%esi
 511:	00 
 512:	00 00                	add    %al,(%rax)
 514:	02 91 5c 05 64 67    	add    0x6764055c(%rcx),%dl
 51a:	74 00                	je     51c <.CDI_sled_id_5_len+0x4f9>
 51c:	02 3b                	add    (%rbx),%bh
 51e:	96                   	xchg   %eax,%esi
 51f:	01 00                	add    %eax,(%rax)
 521:	00 02                	add    %al,(%rdx)
 523:	91                   	xchg   %eax,%ecx
 524:	6f                   	outsl  %ds:(%rsi),(%dx)
 525:	00 03                	add    %al,(%rbx)
 527:	01 08                	add    %ecx,(%rax)
 529:	28 01                	sub    %al,(%rcx)
 52b:	00 00                	add    %al,(%rax)
 52d:	0e                   	(bad)  
 52e:	36 01 00             	add    %eax,%ss:(%rax)
 531:	00 02                	add    %al,(%rdx)
 533:	35 5a 0e 40 00       	xor    $0x400e5a,%eax
 538:	00 00                	add    %al,(%rax)
 53a:	00 00                	add    %al,(%rax)
 53c:	c9                   	leaveq 
 53d:	00 00                	add    %al,(%rax)
 53f:	00 00                	add    %al,(%rax)
 541:	00 00                	add    %al,(%rax)
 543:	00 01                	add    %al,(%rcx)
 545:	9c                   	pushfq 
 546:	c9                   	leaveq 
 547:	01 00                	add    %eax,(%rax)
 549:	00 0a                	add    %cl,(%rdx)
 54b:	64 67 74 00          	fs addr32 je 54f <.CDI_sled_id_5_len+0x52c>
 54f:	02 35 67 00 00 00    	add    0x67(%rip),%dh        # 5bc <.CDI_sled_id_5_len+0x599>
 555:	02 91 6c 00 0f 6f    	add    0x6f0f006c(%rcx),%dl
 55b:	75 74                	jne    5d1 <.CDI_sled_id_5_len+0x5ae>
 55d:	00 02                	add    %al,(%rdx)
 55f:	31 aa 0d 40 00 00    	xor    %ebp,0x400d(%rdx)
 565:	00 00                	add    %al,(%rax)
 567:	00 b0 00 00 00 00    	add    %dh,0x0(%rax)
 56d:	00 00                	add    %al,(%rax)
 56f:	00 01                	add    %al,(%rcx)
 571:	9c                   	pushfq 
 572:	f3 01 00             	repz add %eax,(%rax)
 575:	00 0a                	add    %cl,(%rdx)
 577:	63 00                	movslq (%rax),%eax
 579:	02 31                	add    (%rcx),%dh
 57b:	67 00 00             	add    %al,(%eax)
 57e:	00 02                	add    %al,(%rdx)
 580:	91                   	xchg   %eax,%ecx
 581:	6c                   	insb   (%dx),%es:(%rdi)
 582:	00 10                	add    %dl,(%rax)
 584:	20 01                	and    %al,(%rcx)
 586:	00 00                	add    %al,(%rax)
 588:	01 05 08 0d 40 00    	add    %eax,0x400d08(%rip)        # 401296 <_CDI_printf.s.outchar_TO_printf.s.tfp_printf_1+0x1b1>
 58e:	00 00                	add    %al,(%rax)
 590:	00 00                	add    %al,(%rax)
 592:	a2 00 00 00 00 00 00 	movabs %al,0x100000000000000
 599:	00 01 
 59b:	9c                   	pushfq 
 59c:	0a 63 00             	or     0x0(%rbx),%ah
 59f:	01 05 67 00 00 00    	add    %eax,0x67(%rip)        # 60c <.CDI_sled_id_5_len+0x5e9>
 5a5:	02                   	.byte 0x2
 5a6:	91                   	xchg   %eax,%ecx
 5a7:	6c                   	insb   (%dx),%es:(%rdi)
	...

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 11                	add    %edx,(%rcx)
   2:	01 25 0e 13 0b 03    	add    %esp,0x30b130e(%rip)        # 30b1316 <_end+0x2aaf5be>
   8:	0e                   	(bad)  
   9:	1b 0e                	sbb    (%rsi),%ecx
   b:	11 01                	adc    %eax,(%rcx)
   d:	12 07                	adc    (%rdi),%al
   f:	10 17                	adc    %dl,(%rdi)
  11:	00 00                	add    %al,(%rax)
  13:	02 24 00             	add    (%rax,%rax,1),%ah
  16:	0b 0b                	or     (%rbx),%ecx
  18:	3e 0b 03             	or     %ds:(%rbx),%eax
  1b:	0e                   	(bad)  
  1c:	00 00                	add    %al,(%rax)
  1e:	03 26                	add    (%rsi),%esp
  20:	00 49 13             	add    %cl,0x13(%rcx)
  23:	00 00                	add    %al,(%rax)
  25:	04 01                	add    $0x1,%al
  27:	01 49 13             	add    %ecx,0x13(%rcx)
  2a:	01 13                	add    %edx,(%rbx)
  2c:	00 00                	add    %al,(%rax)
  2e:	05 21 00 49 13       	add    $0x13490021,%eax
  33:	2f                   	(bad)  
  34:	0b 00                	or     (%rax),%eax
  36:	00 06                	add    %al,(%rsi)
  38:	24 00                	and    $0x0,%al
  3a:	0b 0b                	or     (%rbx),%ecx
  3c:	3e 0b 03             	or     %ds:(%rbx),%eax
  3f:	08 00                	or     %al,(%rax)
  41:	00 07                	add    %al,(%rdi)
  43:	34 00                	xor    $0x0,%al
  45:	03 08                	add    (%rax),%ecx
  47:	3a 0b                	cmp    (%rbx),%cl
  49:	3b 0b                	cmp    (%rbx),%ecx
  4b:	49 13 02             	adc    (%r10),%rax
  4e:	18 00                	sbb    %al,(%rax)
  50:	00 08                	add    %cl,(%rax)
  52:	34 00                	xor    $0x0,%al
  54:	03 0e                	add    (%rsi),%ecx
  56:	3a 0b                	cmp    (%rbx),%cl
  58:	3b 0b                	cmp    (%rbx),%ecx
  5a:	49 13 02             	adc    (%r10),%rax
  5d:	18 00                	sbb    %al,(%rax)
  5f:	00 09                	add    %cl,(%rcx)
  61:	34 00                	xor    $0x0,%al
  63:	03 0e                	add    (%rsi),%ecx
  65:	3a 0b                	cmp    (%rbx),%cl
  67:	3b 0b                	cmp    (%rbx),%ecx
  69:	49 13 3f             	adc    (%r15),%rdi
  6c:	19 02                	sbb    %eax,(%rdx)
  6e:	18 00                	sbb    %al,(%rax)
  70:	00 0a                	add    %cl,(%rdx)
  72:	2e 00 3f             	add    %bh,%cs:(%rdi)
  75:	19 03                	sbb    %eax,(%rbx)
  77:	0e                   	(bad)  
  78:	3a 0b                	cmp    (%rbx),%cl
  7a:	3b 0b                	cmp    (%rbx),%ecx
  7c:	49 13 11             	adc    (%r9),%rdx
  7f:	01 12                	add    %edx,(%rdx)
  81:	07                   	(bad)  
  82:	40 18 96 42 19 00 00 	sbb    %dl,0x1942(%rsi)
  89:	0b 2e                	or     (%rsi),%ebp
  8b:	01 3f                	add    %edi,(%rdi)
  8d:	19 03                	sbb    %eax,(%rbx)
  8f:	0e                   	(bad)  
  90:	3a 0b                	cmp    (%rbx),%cl
  92:	3b 0b                	cmp    (%rbx),%ecx
  94:	27                   	(bad)  
  95:	19 49 13             	sbb    %ecx,0x13(%rcx)
  98:	11 01                	adc    %eax,(%rcx)
  9a:	12 07                	adc    (%rdi),%al
  9c:	40 18 96 42 19 01 13 	sbb    %dl,0x13011942(%rsi)
  a3:	00 00                	add    %al,(%rax)
  a5:	0c 15                	or     $0x15,%al
  a7:	01 27                	add    %esp,(%rdi)
  a9:	19 01                	sbb    %eax,(%rcx)
  ab:	13 00                	adc    (%rax),%eax
  ad:	00 0d 05 00 49 13    	add    %cl,0x13490005(%rip)        # 134900b8 <_end+0x12e8e360>
  b3:	00 00                	add    %al,(%rax)
  b5:	0e                   	(bad)  
  b6:	0f 00 0b             	str    (%rbx)
  b9:	0b 49 13             	or     0x13(%rcx),%ecx
  bc:	00 00                	add    %al,(%rax)
  be:	0f 2e 01             	ucomiss (%rcx),%xmm0
  c1:	3f                   	(bad)  
  c2:	19 03                	sbb    %eax,(%rbx)
  c4:	0e                   	(bad)  
  c5:	3a 0b                	cmp    (%rbx),%cl
  c7:	3b 0b                	cmp    (%rbx),%ecx
  c9:	27                   	(bad)  
  ca:	19 11                	sbb    %edx,(%rcx)
  cc:	01 12                	add    %edx,(%rdx)
  ce:	07                   	(bad)  
  cf:	40 18 97 42 19 01 13 	sbb    %dl,0x13011942(%rdi)
  d6:	00 00                	add    %al,(%rax)
  d8:	10 05 00 03 08 3a    	adc    %al,0x3a080300(%rip)        # 3a0803de <_end+0x39a7e686>
  de:	0b 3b                	or     (%rbx),%edi
  e0:	0b 49 13             	or     0x13(%rcx),%ecx
  e3:	02 18                	add    (%rax),%bl
  e5:	00 00                	add    %al,(%rax)
  e7:	11 2e                	adc    %ebp,(%rsi)
  e9:	01 03                	add    %eax,(%rbx)
  eb:	08 3a                	or     %bh,(%rdx)
  ed:	0b 3b                	or     (%rbx),%edi
  ef:	0b 27                	or     (%rdi),%esp
  f1:	19 49 13             	sbb    %ecx,0x13(%rcx)
  f4:	11 01                	adc    %eax,(%rcx)
  f6:	12 07                	adc    (%rdi),%al
  f8:	40 18 96 42 19 00 00 	sbb    %dl,0x1942(%rsi)
  ff:	00 01                	add    %al,(%rcx)
 101:	11 01                	adc    %eax,(%rcx)
 103:	25 0e 13 0b 03       	and    $0x30b130e,%eax
 108:	0e                   	(bad)  
 109:	1b 0e                	sbb    (%rsi),%ecx
 10b:	11 01                	adc    %eax,(%rcx)
 10d:	12 07                	adc    (%rdi),%al
 10f:	10 17                	adc    %dl,(%rdi)
 111:	00 00                	add    %al,(%rax)
 113:	02 16                	add    (%rsi),%dl
 115:	00 03                	add    %al,(%rbx)
 117:	0e                   	(bad)  
 118:	3a 0b                	cmp    (%rbx),%cl
 11a:	3b 0b                	cmp    (%rbx),%ecx
 11c:	00 00                	add    %al,(%rax)
 11e:	03 24 00             	add    (%rax,%rax,1),%esp
 121:	0b 0b                	or     (%rbx),%ecx
 123:	3e 0b 03             	or     %ds:(%rbx),%eax
 126:	0e                   	(bad)  
 127:	00 00                	add    %al,(%rax)
 129:	04 16                	add    $0x16,%al
 12b:	00 03                	add    %al,(%rbx)
 12d:	0e                   	(bad)  
 12e:	3a 0b                	cmp    (%rbx),%cl
 130:	3b 0b                	cmp    (%rbx),%ecx
 132:	49 13 00             	adc    (%r8),%rax
 135:	00 05 34 00 03 08    	add    %al,0x8030034(%rip)        # 803016f <_end+0x7a2e417>
 13b:	3a 0b                	cmp    (%rbx),%cl
 13d:	3b 0b                	cmp    (%rbx),%ecx
 13f:	49 13 02             	adc    (%r10),%rax
 142:	18 00                	sbb    %al,(%rax)
 144:	00 06                	add    %al,(%rsi)
 146:	0f 00 0b             	str    (%rbx)
 149:	0b 49 13             	or     0x13(%rcx),%ecx
 14c:	00 00                	add    %al,(%rax)
 14e:	07                   	(bad)  
 14f:	01 01                	add    %eax,(%rcx)
 151:	49 13 01             	adc    (%r9),%rax
 154:	13 00                	adc    (%rax),%eax
 156:	00 08                	add    %cl,(%rax)
 158:	21 00                	and    %eax,(%rax)
 15a:	49 13 2f             	adc    (%r15),%rbp
 15d:	0b 00                	or     (%rax),%eax
 15f:	00 09                	add    %cl,(%rcx)
 161:	2e 01 3f             	add    %edi,%cs:(%rdi)
 164:	19 03                	sbb    %eax,(%rbx)
 166:	0e                   	(bad)  
 167:	3a 0b                	cmp    (%rbx),%cl
 169:	3b 0b                	cmp    (%rbx),%ecx
 16b:	27                   	(bad)  
 16c:	19 11                	sbb    %edx,(%rcx)
 16e:	01 12                	add    %edx,(%rdx)
 170:	07                   	(bad)  
 171:	40 18 96 42 19 01 13 	sbb    %dl,0x13011942(%rsi)
 178:	00 00                	add    %al,(%rax)
 17a:	0a 05 00 03 08 3a    	or     0x3a080300(%rip),%al        # 3a080480 <_end+0x39a7e728>
 180:	0b 3b                	or     (%rbx),%edi
 182:	0b 49 13             	or     0x13(%rcx),%ecx
 185:	02 18                	add    (%rax),%bl
 187:	00 00                	add    %al,(%rax)
 189:	0b 18                	or     (%rax),%ebx
 18b:	00 00                	add    %al,(%rax)
 18d:	00 0c 0a             	add    %cl,(%rdx,%rcx,1)
 190:	00 03                	add    %al,(%rbx)
 192:	0e                   	(bad)  
 193:	3a 0b                	cmp    (%rbx),%cl
 195:	3b 0b                	cmp    (%rbx),%ecx
 197:	11 01                	adc    %eax,(%rcx)
 199:	00 00                	add    %al,(%rax)
 19b:	0d 0b 01 55 17       	or     $0x1755010b,%eax
 1a0:	01 13                	add    %edx,(%rbx)
 1a2:	00 00                	add    %al,(%rax)
 1a4:	0e                   	(bad)  
 1a5:	2e 01 03             	add    %eax,%cs:(%rbx)
 1a8:	0e                   	(bad)  
 1a9:	3a 0b                	cmp    (%rbx),%cl
 1ab:	3b 0b                	cmp    (%rbx),%ecx
 1ad:	27                   	(bad)  
 1ae:	19 11                	sbb    %edx,(%rcx)
 1b0:	01 12                	add    %edx,(%rdx)
 1b2:	07                   	(bad)  
 1b3:	40 18 96 42 19 01 13 	sbb    %dl,0x13011942(%rsi)
 1ba:	00 00                	add    %al,(%rax)
 1bc:	0f 2e 01             	ucomiss (%rcx),%xmm0
 1bf:	03 08                	add    (%rax),%ecx
 1c1:	3a 0b                	cmp    (%rbx),%cl
 1c3:	3b 0b                	cmp    (%rbx),%ecx
 1c5:	27                   	(bad)  
 1c6:	19 11                	sbb    %edx,(%rcx)
 1c8:	01 12                	add    %edx,(%rdx)
 1ca:	07                   	(bad)  
 1cb:	40 18 97 42 19 01 13 	sbb    %dl,0x13011942(%rdi)
 1d2:	00 00                	add    %al,(%rax)
 1d4:	10 2e                	adc    %ch,(%rsi)
 1d6:	01 3f                	add    %edi,(%rdi)
 1d8:	19 03                	sbb    %eax,(%rbx)
 1da:	0e                   	(bad)  
 1db:	3a 0b                	cmp    (%rbx),%cl
 1dd:	3b 0b                	cmp    (%rbx),%ecx
 1df:	27                   	(bad)  
 1e0:	19 11                	sbb    %edx,(%rcx)
 1e2:	01 12                	add    %edx,(%rdx)
 1e4:	07                   	(bad)  
 1e5:	40 18 97 42 19 00 00 	sbb    %dl,0x1942(%rdi)
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	d8 00                	fadds  (%rax)
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	22 00                	and    (%rax),%al
   8:	00 00                	add    %al,(%rax)
   a:	01 01                	add    %eax,(%rcx)
   c:	fb                   	sti    
   d:	0e                   	(bad)  
   e:	0d 00 01 01 01       	or     $0x1010100,%eax
  13:	01 00                	add    %eax,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	01 00                	add    %eax,(%rax)
  19:	00 01                	add    %al,(%rcx)
  1b:	00 62 65             	add    %ah,0x65(%rdx)
  1e:	6e                   	outsb  %ds:(%rsi),(%dx)
  1f:	63 68 6d             	movslq 0x6d(%rax),%ebp
  22:	61                   	(bad)  
  23:	72 6b                	jb     90 <.CDI_sled_id_5_len+0x6d>
  25:	2e 63 00             	movslq %cs:(%rax),%eax
  28:	00 00                	add    %al,(%rax)
  2a:	00 00                	add    %al,(%rax)
  2c:	00 09                	add    %cl,(%rcx)
  2e:	02 76 04             	add    0x4(%rsi),%dh
  31:	40 00 00             	add    %al,(%rax)
  34:	00 00                	add    %al,(%rax)
  36:	00 03                	add    %al,(%rbx)
  38:	0b 01                	or     (%rcx),%eax
  3a:	08 14 68             	or     %dl,(%rax,%rbp,2)
  3d:	08 9f 08 9f 08 21    	or     %bl,0x21089f08(%rdi)
  43:	76 08                	jbe    4d <.CDI_sled_id_5_len+0x2a>
  45:	3d 08 4b 08 21       	cmp    $0x21084b08,%eax
  4a:	08 4b 59             	or     %cl,0x59(%rbx)
  4d:	02 88 01 16 83 76    	add    0x76831601(%rax),%cl
  53:	e5 e6                	in     $0xe6,%eax
  55:	78 4b                	js     a2 <.CDI_sled_id_5_len+0x7f>
  57:	9f                   	lahf   
  58:	91                   	xchg   %eax,%ecx
  59:	9f                   	lahf   
  5a:	9f                   	lahf   
  5b:	ae                   	scas   %es:(%rdi),%al
  5c:	08 3e                	or     %bh,(%rsi)
  5e:	4b 02 32             	rex.WXB add (%r10),%sil
  61:	14 03                	adc    $0x3,%al
  63:	74 66                	je     cb <.CDI_sled_id_5_len+0xa8>
  65:	03 0c 58             	add    (%rax,%rbx,2),%ecx
  68:	22 59 02             	and    0x2(%rcx),%bl
  6b:	67 1a f3             	addr32 sbb %bl,%dh
  6e:	08 f3                	or     %dh,%bl
  70:	02 2e                	add    (%rsi),%ch
  72:	14 30                	adc    $0x30,%al
  74:	67 02 2c 13          	add    (%ebx,%edx,1),%ch
  78:	02 2c 0e             	add    (%rsi,%rcx,1),%ch
  7b:	ce                   	(bad)  
  7c:	08 59 02             	or     %bl,0x2(%rcx)
  7f:	59                   	pop    %rcx
  80:	18 f3                	sbb    %dh,%bl
  82:	08 f3                	or     %dh,%bl
  84:	02 2e                	add    (%rsi),%ch
  86:	15 30 02 2c 13       	adc    $0x132c0230,%eax
  8b:	02 2c 13             	add    (%rbx,%rdx,1),%ch
  8e:	62                   	(bad)  
  8f:	ce                   	(bad)  
  90:	08 59 03             	or     %bl,0x3(%rcx)
  93:	0b 02                	or     (%rdx),%eax
  95:	59                   	pop    %rcx
  96:	01 86 83 02 80 02    	add    %eax,0x2800283(%rsi)
  9c:	13 00                	adc    (%rax),%eax
  9e:	02 04 01             	add    (%rcx,%rax,1),%al
  a1:	06                   	(bad)  
  a2:	f2 06                	repnz (bad) 
  a4:	f3 9f                	repz lahf 
  a6:	83 02 80             	addl   $0xffffff80,(%rdx)
  a9:	02 13                	add    (%rbx),%dl
  ab:	00 02                	add    %al,(%rdx)
  ad:	04 01                	add    $0x1,%al
  af:	06                   	(bad)  
  b0:	f2 06                	repnz (bad) 
  b2:	f3 a0 e7 64 3e 64 59 	repz movabs 0x653d6559643e64e7,%al
  b9:	65 3d 65 
  bc:	08 87 64 3e 64 59    	or     %al,0x59643e64(%rdi)
  c2:	65 3d 65 08 87 64    	gs cmp $0x64870865,%eax
  c8:	3e 64 59             	ds fs pop %rcx
  cb:	65 3d 65 08 86 59    	gs cmp $0x59860865,%eax
  d1:	02 64 16 4b          	add    0x4b(%rsi,%rdx,1),%ah
  d5:	59                   	pop    %rcx
  d6:	9f                   	lahf   
  d7:	02 02                	add    (%rdx),%al
  d9:	00 01                	add    %al,(%rcx)
  db:	01 90 01 00 00 02    	add    %edx,0x2000001(%rax)
  e1:	00 89 00 00 00 01    	add    %cl,0x1000000(%rcx)
  e7:	01 fb                	add    %edi,%ebx
  e9:	0e                   	(bad)  
  ea:	0d 00 01 01 01       	or     $0x1010100,%eax
  ef:	01 00                	add    %eax,(%rax)
  f1:	00 00                	add    %al,(%rax)
  f3:	01 00                	add    %eax,(%rax)
  f5:	00 01                	add    %al,(%rcx)
  f7:	2f                   	(bad)  
  f8:	68 6f 6d 65 2f       	pushq  $0x2f656d6f
  fd:	6d                   	insl   (%dx),%es:(%rdi)
  fe:	69 73 69 6b 65 72 2f 	imul   $0x2f72656b,0x69(%rbx),%esi
 105:	44                   	rex.R
 106:	65 73 6b             	gs jae 174 <.CDI_sled_id_5_len+0x151>
 109:	74 6f                	je     17a <.CDI_sled_id_5_len+0x157>
 10b:	70 2f                	jo     13c <.CDI_sled_id_5_len+0x119>
 10d:	63 64 69 2f          	movslq 0x2f(%rcx,%rbp,2),%esp
 111:	47                   	rex.RXB
 112:	43                   	rex.XB
 113:	43 2f                	rex.XB (bad) 
 115:	67 63 63 2d          	movslq 0x2d(%ebx),%esp
 119:	64 65 73 74          	fs gs jae 191 <.CDI_sled_id_5_len+0x16e>
 11d:	2f                   	(bad)  
 11e:	6c                   	insb   (%dx),%es:(%rdi)
 11f:	69 62 2f 67 63 63 2f 	imul   $0x2f636367,0x2f(%rdx),%esp
 126:	78 38                	js     160 <.CDI_sled_id_5_len+0x13d>
 128:	36 5f                	ss pop %rdi
 12a:	36 34 2d             	ss xor $0x2d,%al
 12d:	70 63                	jo     192 <.CDI_sled_id_5_len+0x16f>
 12f:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
 134:	78 2d                	js     163 <.CDI_sled_id_5_len+0x140>
 136:	67 6e                	outsb  %ds:(%esi),(%dx)
 138:	75 2f                	jne    169 <.CDI_sled_id_5_len+0x146>
 13a:	36 2e 31 2e          	ss xor %ebp,%cs:(%rsi)
 13e:	30 2f                	xor    %ch,(%rdi)
 140:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
 147:	00 00                	add    %al,(%rax)
 149:	6f                   	outsl  %ds:(%rsi),(%dx)
 14a:	75 74                	jne    1c0 <.CDI_sled_id_5_len+0x19d>
 14c:	63 68 61             	movslq 0x61(%rax),%ebp
 14f:	72 2e                	jb     17f <.CDI_sled_id_5_len+0x15c>
 151:	68 00 00 00 00       	pushq  $0x0
 156:	70 72                	jo     1ca <.CDI_sled_id_5_len+0x1a7>
 158:	69 6e 74 66 2e 63 00 	imul   $0x632e66,0x74(%rsi),%ebp
 15f:	00 00                	add    %al,(%rax)
 161:	00 73 74             	add    %dh,0x74(%rbx)
 164:	64 61                	fs (bad) 
 166:	72 67                	jb     1cf <.CDI_sled_id_5_len+0x1ac>
 168:	2e 68 00 01 00 00    	cs pushq $0x100
 16e:	00 00                	add    %al,(%rax)
 170:	09 02                	or     %eax,(%rdx)
 172:	08 0d 40 00 00 00    	or     %cl,0x40(%rip)        # 1b8 <.CDI_sled_id_5_len+0x195>
 178:	00 00                	add    %al,(%rax)
 17a:	16                   	(bad)  
 17b:	91                   	xchg   %eax,%ecx
 17c:	08 78 04             	or     %bh,0x4(%rax)
 17f:	02 03                	add    (%rbx),%al
 181:	27                   	(bad)  
 182:	02 81 01 01 91 08    	add    0x8910101(%rcx),%al
 188:	75 02                	jne    18c <.CDI_sled_id_5_len+0x169>
 18a:	8f 01                	popq   (%rcx)
 18c:	14 c9                	adc    $0xc9,%al
 18e:	00 02                	add    %al,(%rdx)
 190:	04 01                	add    $0x1,%al
 192:	06                   	(bad)  
 193:	66 00 02             	data16 add %al,(%rdx)
 196:	04 03                	add    $0x3,%al
 198:	ac                   	lods   %ds:(%rsi),%al
 199:	00 02                	add    %al,(%rdx)
 19b:	04 04                	add    $0x4,%al
 19d:	74 00                	je     19f <.CDI_sled_id_5_len+0x17c>
 19f:	02 04 02             	add    (%rdx,%rax,1),%al
 1a2:	74 00                	je     1a4 <.CDI_sled_id_5_len+0x181>
 1a4:	02 04 08             	add    (%rax,%rcx,1),%al
 1a7:	58                   	pop    %rax
 1a8:	00 02                	add    %al,(%rdx)
 1aa:	04 08                	add    $0x8,%al
 1ac:	06                   	(bad)  
 1ad:	f3 00 02             	repz add %al,(%rdx)
 1b0:	04 08                	add    $0x8,%al
 1b2:	75 02                	jne    1b6 <.CDI_sled_id_5_len+0x193>
 1b4:	81 01 14 ad 4b e5    	addl   $0xe54bad14,(%rcx)
 1ba:	2f                   	(bad)  
 1bb:	e5 9c                	in     $0x9c,%eax
 1bd:	b0 00                	mov    $0x0,%al
 1bf:	02 04 01             	add    (%rcx,%rax,1),%al
 1c2:	06                   	(bad)  
 1c3:	ac                   	lods   %ds:(%rsi),%al
 1c4:	06                   	(bad)  
 1c5:	67 d7                	xlat   %ds:(%ebx)
 1c7:	02 bd 01 15 02 59    	add    0x59021501(%rbp),%bh
 1cd:	17                   	(bad)  
 1ce:	02 2d 14 59 91 08    	add    0x8915914(%rip),%ch        # 8915ae8 <_end+0x8313d90>
 1d4:	31 75 75             	xor    %esi,0x75(%rbp)
 1d7:	08 9f 91 08 9f 76    	or     %bl,0x769f0891(%rdi)
 1dd:	00 02                	add    %al,(%rdx)
 1df:	04 01                	add    $0x1,%al
 1e1:	06                   	(bad)  
 1e2:	90                   	nop
 1e3:	06                   	(bad)  
 1e4:	91                   	xchg   %eax,%ecx
 1e5:	75 2f                	jne    216 <.CDI_sled_id_5_len+0x1f3>
 1e7:	02 2c 13             	add    (%rbx,%rdx,1),%ch
 1ea:	08 9c 00 02 04 01 06 	or     %bl,0x6010402(%rax,%rax,1)
 1f1:	90                   	nop
 1f2:	06                   	(bad)  
 1f3:	95                   	xchg   %eax,%ebp
 1f4:	ad                   	lods   %ds:(%rsi),%eax
 1f5:	d7                   	xlat   %ds:(%rbx)
 1f6:	75 03                	jne    1fb <.CDI_sled_id_5_len+0x1d8>
 1f8:	22 02                	and    (%rdx),%al
 1fa:	2f                   	(bad)  
 1fb:	01 03                	add    %eax,(%rbx)
 1fd:	5e                   	pop    %rsi
 1fe:	58                   	pop    %rax
 1ff:	03 22                	add    (%rdx),%esp
 201:	08 2e                	or     %ch,(%rsi)
 203:	03 5e 58             	add    0x58(%rsi),%ebx
 206:	03 22                	add    (%rdx),%esp
 208:	d6                   	(bad)  
 209:	03 63 58             	add    0x58(%rbx),%esp
 20c:	02 42 12             	add    0x12(%rdx),%al
 20f:	67 00 02             	add    %al,(%edx)
 212:	04 01                	add    $0x1,%al
 214:	06                   	(bad)  
 215:	90                   	nop
 216:	06                   	(bad)  
 217:	9f                   	lahf   
 218:	d7                   	xlat   %ds:(%rbx)
 219:	a0 9f 9f 9f 9f f3 5b 	movabs 0x2f35bf39f9f9f9f,%al
 220:	f3 02 
 222:	42 12 67 9f          	rex.X adc -0x61(%rdi),%spl
 226:	9f                   	lahf   
 227:	9f                   	lahf   
 228:	f3 5a                	repz pop %rdx
 22a:	02 42 12             	add    0x12(%rdx),%al
 22d:	9f                   	lahf   
 22e:	30 02                	xor    %al,(%rdx)
 230:	4a 13 30             	rex.WX adc (%rax),%rsi
 233:	a0 22 9f d7 2f f1 00 	movabs 0x40200f12fd79f22,%al
 23a:	02 04 
 23c:	01 06                	add    %eax,(%rsi)
 23e:	08 82 06 92 2f 00    	or     %al,0x2f9206(%rdx)
 244:	02 04 01             	add    (%rcx,%rax,1),%al
 247:	06                   	(bad)  
 248:	90                   	nop
 249:	00 02                	add    %al,(%rdx)
 24b:	04 02                	add    $0x2,%al
 24d:	74 00                	je     24f <.CDI_sled_id_5_len+0x22c>
 24f:	02 04 04             	add    (%rsp,%rax,1),%al
 252:	58                   	pop    %rax
 253:	06                   	(bad)  
 254:	73 08                	jae    25e <.CDI_sled_id_5_len+0x23b>
 256:	5a                   	pop    %rdx
 257:	2f                   	(bad)  
 258:	d5                   	(bad)  
 259:	03 40 02             	add    0x2(%rax),%eax
 25c:	24 01                	and    $0x1,%al
 25e:	03 c6                	add    %esi,%eax
 260:	00 02                	add    %al,(%rdx)
 262:	28 01                	sub    %al,(%rcx)
 264:	03 52 2e             	add    0x2e(%rdx),%edx
 267:	03 2e                	add    (%rsi),%ebp
 269:	20 02                	and    %al,(%rdx)
 26b:	be 01 00 01 01       	mov    $0x1010001,%esi

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	63 69 70             	movslq 0x70(%rcx),%ebp
   3:	68 65 72 74 65       	pushq  $0x65747265
   8:	78 74                	js     7e <.CDI_sled_id_5_len+0x5b>
   a:	00 63 69             	add    %ah,0x69(%rbx)
   d:	70 68                	jo     77 <.CDI_sled_id_5_len+0x54>
   f:	65 72 5f             	gs jb  71 <.CDI_sled_id_5_len+0x4e>
  12:	6d                   	insl   (%dx),%es:(%rdi)
  13:	61                   	(bad)  
  14:	69 6e 00 63 6f 75 6e 	imul   $0x6e756f63,0x0(%rsi),%ebp
  1b:	74 00                	je     1d <.CDI_sled_id_10_len>
  1d:	64 65 6c             	fs gs insb (%dx),%es:(%rdi)
  20:	74 61                	je     83 <.CDI_sled_id_5_len+0x60>
  22:	00 63 69             	add    %ah,0x69(%rbx)
  25:	70 68                	jo     8f <.CDI_sled_id_5_len+0x6c>
  27:	65 72 5f             	gs jb  89 <.CDI_sled_id_5_len+0x66>
  2a:	74 79                	je     a5 <.CDI_sled_id_5_len+0x82>
  2c:	70 65                	jo     93 <.CDI_sled_id_5_len+0x70>
  2e:	00 70 6c             	add    %dh,0x6c(%rax)
  31:	61                   	(bad)  
  32:	69 6e 74 65 78 74 00 	imul   $0x747865,0x74(%rsi),%ebp
  39:	65 6e                	outsb  %gs:(%rsi),(%dx)
  3b:	63 69 70             	movslq 0x70(%rcx),%ebp
  3e:	68 65 72 00 2f       	pushq  $0x2f007265
  43:	68 6f 6d 65 2f       	pushq  $0x2f656d6f
  48:	6d                   	insl   (%dx),%es:(%rdi)
  49:	69 73 69 6b 65 72 2f 	imul   $0x2f72656b,0x69(%rbx),%esi
  50:	44                   	rex.R
  51:	65 73 6b             	gs jae bf <.CDI_sled_id_5_len+0x9c>
  54:	74 6f                	je     c5 <.CDI_sled_id_5_len+0xa2>
  56:	70 2f                	jo     87 <.CDI_sled_id_5_len+0x64>
  58:	63 64 69 2f          	movslq 0x2f(%rcx,%rbp,2),%esp
  5c:	63 6f 6e             	movslq 0x6e(%rdi),%ebp
  5f:	76 65                	jbe    c6 <.CDI_sled_id_5_len+0xa3>
  61:	72 74                	jb     d7 <.CDI_sled_id_5_len+0xb4>
  63:	65 72 2f             	gs jb  95 <.CDI_sled_id_5_len+0x72>
  66:	69 6d 70 72 6f 76 65 	imul   $0x65766f72,0x70(%rbp),%ebp
  6d:	64 5f                	fs pop %rdi
  6f:	62                   	(bad)  
  70:	65 6e                	outsb  %gs:(%rsi),(%dx)
  72:	63 68 6d             	movslq 0x6d(%rax),%ebp
  75:	61                   	(bad)  
  76:	72 6b                	jb     e3 <.CDI_sled_id_5_len+0xc0>
  78:	00 63 69             	add    %ah,0x69(%rbx)
  7b:	70 68                	jo     e5 <.CDI_sled_id_5_len+0xc2>
  7d:	65 72 72             	gs jb  f2 <.CDI_sled_id_5_len+0xcf>
  80:	65 66 00 64 65 63    	data16 add %ah,%gs:0x63(%rbp,%riz,2)
  86:	69 70 68 65 72 00 4c 	imul   $0x4c007265,0x68(%rax),%esi
  8d:	6f                   	outsl  %ds:(%rsi),(%dx)
  8e:	6f                   	outsl  %ds:(%rsi),(%dx)
  8f:	70 73                	jo     104 <.CDI_sled_id_5_len+0xe1>
  91:	00 75 6e             	add    %dh,0x6e(%rbp)
  94:	73 69                	jae    ff <.CDI_sled_id_5_len+0xdc>
  96:	67 6e                	outsb  %ds:(%esi),(%dx)
  98:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
  9d:	74 00                	je     9f <.CDI_sled_id_5_len+0x7c>
  9f:	62                   	(bad)  
  a0:	65 6e                	outsb  %gs:(%rsi),(%dx)
  a2:	63 68 6d             	movslq 0x6d(%rax),%ebp
  a5:	61                   	(bad)  
  a6:	72 6b                	jb     113 <.CDI_sled_id_5_len+0xf0>
  a8:	2e 63 00             	movslq %cs:(%rax),%eax
  ab:	64 69 73 6b 00 6e 65 	imul   $0x77656e00,%fs:0x6b(%rbx),%esi
  b2:	77 
  b3:	70 6c                	jo     121 <.CDI_sled_id_5_len+0xfe>
  b5:	61                   	(bad)  
  b6:	69 6e 00 68 61 6e 6f 	imul   $0x6f6e6168,0x0(%rsi),%ebp
  bd:	69 5f 6d 61 69 6e 00 	imul   $0x6e6961,0x6d(%rdi),%ebx
  c4:	73 69                	jae    12f <.CDI_sled_id_5_len+0x10c>
  c6:	7a 65                	jp     12d <.CDI_sled_id_5_len+0x10a>
  c8:	74 79                	je     143 <.CDI_sled_id_5_len+0x120>
  ca:	70 65                	jo     131 <.CDI_sled_id_5_len+0x10e>
  cc:	00 47 4e             	add    %al,0x4e(%rdi)
  cf:	55                   	push   %rbp
  d0:	20 43 31             	and    %al,0x31(%rbx)
  d3:	31 20                	xor    %esp,(%rax)
  d5:	36 2e 31 2e          	ss xor %ebp,%cs:(%rsi)
  d9:	30 20                	xor    %ah,(%rax)
  db:	2d 6d 74 75 6e       	sub    $0x6e75746d,%eax
  e0:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
  e6:	72 69                	jb     151 <.CDI_sled_id_5_len+0x12e>
  e8:	63 20                	movslq (%rax),%esp
  ea:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
  ef:	68 3d 78 38 36       	pushq  $0x3638783d
  f4:	2d 36 34 20 2d       	sub    $0x2d203436,%eax
  f9:	67 00 6c 6f 6e       	add    %ch,0x6e(%edi,%ebp,2)
  fe:	67 20 69 6e          	and    %ch,0x6e(%ecx)
 102:	74 00                	je     104 <.CDI_sled_id_5_len+0xe1>
 104:	6b 65 79 74          	imul   $0x74,0x79(%rbp),%esp
 108:	65 78 74             	gs js  17f <.CDI_sled_id_5_len+0x15c>
 10b:	00 70 72             	add    %dh,0x72(%rax)
 10e:	69 6e 74 66 2e 63 00 	imul   $0x632e66,0x74(%rsi),%ebp
 115:	74 66                	je     17d <.CDI_sled_id_5_len+0x15a>
 117:	70 5f                	jo     178 <.CDI_sled_id_5_len+0x155>
 119:	70 72                	jo     18d <.CDI_sled_id_5_len+0x16a>
 11b:	69 6e 74 66 00 6f 75 	imul   $0x756f0066,0x74(%rsi),%ebp
 122:	74 63                	je     187 <.CDI_sled_id_5_len+0x164>
 124:	68 61 72 00 75       	pushq  $0x75007261
 129:	6e                   	outsb  %ds:(%rsi),(%dx)
 12a:	73 69                	jae    195 <.CDI_sled_id_5_len+0x172>
 12c:	67 6e                	outsb  %ds:(%esi),(%dx)
 12e:	65 64 20 63 68       	gs and %ah,%fs:0x68(%rbx)
 133:	61                   	(bad)  
 134:	72 00                	jb     136 <.CDI_sled_id_5_len+0x113>
 136:	6f                   	outsl  %ds:(%rsi),(%dx)
 137:	75 74                	jne    1ad <.CDI_sled_id_5_len+0x18a>
 139:	44                   	rex.R
 13a:	67 74 00             	addr32 je 13d <.CDI_sled_id_5_len+0x11a>
 13d:	64 69 76 4f 75 74 00 	imul   $0x5f007475,%fs:0x4f(%rsi),%esi
 144:	5f 
 145:	5f                   	pop    %rdi
 146:	67 6e                	outsb  %ds:(%esi),(%dx)
 148:	75 63                	jne    1ad <.CDI_sled_id_5_len+0x18a>
 14a:	5f                   	pop    %rdi
 14b:	76 61                	jbe    1ae <.CDI_sled_id_5_len+0x18b>
 14d:	5f                   	pop    %rdi
 14e:	6c                   	insb   (%dx),%es:(%rdi)
 14f:	69 73 74 00 61 62 6f 	imul   $0x6f626100,0x74(%rbx),%esi
 156:	72 74                	jb     1cc <.CDI_sled_id_5_len+0x1a9>
	...

Disassembly of section .debug_ranges:

0000000000000000 <.debug_ranges>:
   0:	e2 03                	loop   5 <.debug_msg_len-0x7>
   2:	00 00                	add    %al,(%rax)
   4:	00 00                	add    %al,(%rax)
   6:	00 00                	add    %al,(%rax)
   8:	bd 07 00 00 00       	mov    $0x7,%ebp
   d:	00 00                	add    %al,(%rax)
   f:	00 e7                	add    %ah,%bh
  11:	07                   	(bad)  
  12:	00 00                	add    %al,(%rax)
  14:	00 00                	add    %al,(%rax)
  16:	00 00                	add    %al,(%rax)
  18:	e8 07 00 00 00       	callq  24 <.CDI_sled_id_5_len+0x1>
	...
