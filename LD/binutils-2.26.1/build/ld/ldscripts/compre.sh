standard_file=elf32_x86_64.x
for file in `ls -I compre.sh`
do
   echo $file
   diff $standard_file $file
done > outputfile
