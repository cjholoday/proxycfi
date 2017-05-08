for file in `ls -1 $dir/$files`
do
   echo $file
   diff standard.file $file
done > outputfile
