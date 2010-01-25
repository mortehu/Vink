var last_path = "loading";
var last_href = "";

function set_path(path, args)
{
  if(path == last_path)
    return;

  if(last_path.length)
    $('#' + last_path).hide();

  last_path = path;

  $('#' + path).show();
}

function location_updated()
{
  if(location.href == last_href)
    return;

  last_href = location.href;

  var href_components = location.href.split('#', 2);

  if(href_components.length < 2)
  {
    set_path('incoming');

    return;
  }

  var args = href_components[1].split('/');

  while(args.length && !args[0].length)
    args.shift();

  if(!args.length)
  {
    set_path('incoming');

    return;
  }

  var path = args[0];
  args.shift();

  set_path(path, args);
}

location_updated();

setInterval("location_updated()", 100);

$('#search-text').focus();
