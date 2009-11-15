<?
header('HTTP/1.0 500 Internal Server Error');
require_once('header.inc.php');
?>
<h1>500 Internal Server Error</h1>
<p>The page could not be shown because of an internal server error: <?=$error?></p>
<?require_once('footer.inc.php');?>
