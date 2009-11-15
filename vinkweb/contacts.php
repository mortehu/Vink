<?
require_once('config.inc.php');
require_once('session.inc.php');
require_once('header.inc.php');

if(array_key_exists('vink-new-contact-jid', $_POST)
   && array_key_exists('vink-new-contact-name', $_POST))
{
  $jid = trim($_POST['vink-new-contact-jid']);
  $name = trim($_POST['vink-new-contact-name']);

  @pg_query_params($vink, 'INSERT INTO vink_contacts (user_id, jid, name) VALUES ($1, $2, $3)',
                   array($vink_userid, $jid, $name));
}

$contacts_res = @pg_query_params($vink, 'SELECT * FROM vink_contacts WHERE user_id = $1 ORDER BY name',
                                 array($vink_userid));
?>
<h1>Contacts</h1>
<form method='post' action='contacts.php'>
  <table cellspacing='0' cellpadding='3'>
    <colgroup><col/><col width='250'/><col width='200'/></colgroup>
    <tr><th></th><th>JID (Address)</th><th>Name</th></tr>
    <? while($contacts_row = @pg_fetch_array($contacts_res)) { ?>
      <tr>
        <td><input type='checkbox' name='vink-contact-<?=$contact_row['id']?>'/></td>
        <td><?=$contacts_row['jid']?></td>
        <td><?=$contacts_row['name']?></td>
      </tr>
    <? } ?>
      <tr>
        <td></td>
        <td><input name='vink-new-contact-jid' type='text' style='width: 250px'/></td>
        <td><input name='vink-new-contact-name' type='text' style='width: 200px'/></td>
        <td><input type='submit' value='Add contact'/></td>
      </tr>
  </table>
</form>
<?
require_once('footer.inc.php');
?>
