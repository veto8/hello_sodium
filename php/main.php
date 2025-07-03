<?php 
class ClassSodium
{
   public function __construct()
   {
        $sign_pair = sodium_crypto_sign_keypair();
        $sign_secret = sodium_crypto_sign_secretkey($sign_pair);
        $sign_public = sodium_crypto_sign_publickey($sign_pair);
        $message = '123456';
        $message_signed = sodium_crypto_sign($message, $sign_secret);
        $message_signed2 = sodium_crypto_sign($message, $sign_secret);
        $message_signed3 = sodium_crypto_sign($message, $sign_secret);		
        //$smessage = sodium_crypto_sign_open($message_signed, $sign_public);
        //echo $smessage;
        //echo $message_signed.'<br>';
        echo sodium_bin2hex($message_signed);
	echo "-----";
        echo sodium_bin2hex($message_signed2);
	echo "-----";	
        echo sodium_bin2hex($message_signed3);	
         
   }

}

$s = new ClassSodium();

?>
