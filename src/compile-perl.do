dependon compile conf-perlinclude
formake "sed 's} gcc} gcc '"'"`head -1 perl-include`"'"'}' < compile >" $1
formake "chmod 755 $1"
sed 's} gcc} gcc '"`head -1 perl-include`"'}' <compile
chmod 755 $3
exit 0
