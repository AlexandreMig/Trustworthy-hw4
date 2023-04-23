gcc alice.c -lssl -lcrypto -lzmq -o alice
gcc bob.c -lssl -lcrypto -lzmq -o bob
#=========================================
./bob Bob_DSA_SK.txt Bob_DSA_PK.txt Bob_DH_SK.txt Bob_DH_PK.txt Alice_DSA_PK.txt >> bob.log &
./alice Alice_DSA_SK.txt Alice_DSA_PK.txt Alice_DH_SK.txt Alice_DH_PK.txt Bob_DSA_PK.txt >> alice.log
#=========================================
if cmp -s "Correct_Agreement.txt" "DH_Key_Agreement_Alice.txt"
then
   echo "Alice DH Agreemnet is correct."
else
   echo "Alice DH Agreement does not match!"
fi 
#=========================================
if cmp -s "Correct_Agreement.txt" "DH_Key_Agreement_Bob.txt"
then
   echo "Bob DH Agreemnet is correct."
else
   echo "Bob DH Agreement does not match!"
fi
#=========================================
echo "$(cat Signature_Alice.txt)"
echo "$(cat Verification_Result_Alice.txt)"
#=========================================
echo "$(cat Signature_Bob.txt)"
echo "$(cat Verification_Result_Bob.txt)"
#=========================================