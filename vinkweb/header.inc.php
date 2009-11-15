<?
header('Content-Type: text/html;charset=utf-8');
?>
<html>
  <head>
    <meta type='http-equiv' name='Content-Type' value='text/html; charset=utf-8' />
    <title>Vinkweb</title>
    <style type='text/css'>
      @import 'style.css';
    </style>
  </head>
  <body>
    <div style='text-align: right; border-bottom: 1px solid black; padding: 5px 10px; margin-bottom: 10px'>
<?
if(isset($vink_userid))
{
  ?>
      Logged in as #<?=$vink_userid?>
    </div>
    <ul class='top-menu'>
      <li><a href='/'>Inbox</a></li>
      <li><a href='/'>Archive</a></li>
      <li><a href='/'>Trash</a></li>
      <li><a href='/'>Spam</a></li>
      <li class='contacts'><a href='contacts.php'>Contacts</a></li>
      <div style='clear:both'></div>
    </ul>
  <?
}
else
{
  ?>
    <form method='post' action='<?=$_GET['REQUEST_URI']?>' style='margin: 0' />
      User: <input type='text' size='10' name='vink-user' value='' style='margin-right: 5px' />
      Password: <input type='password' size='10' name='vink-secret' value='' style='margin-right: 5px' />
      <input type='submit' value='Log in' />
    </form>
  </div>
  <?
}
?>
