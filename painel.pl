#!/usr/bin/perl

use CGI;
use DBI;

my $cgi = CGI->new;

my $dbh = DBI->connect( 'dbi:SQLite:dbname=database.db', undef, undef );

# update status
if ( $cgi->param('status') ) {
    my $status = $cgi->param('status') || 'offline';

    $dbh->do(
        qq{
        UPDATE status_links SET status = '$status' WHERE id = 1;
    }
    );
}

my $sth =
  $dbh->prepare( 'SELECT status FROM status_links ORDER BY id DESC LIMIT 1;' );
$sth->execute;

# string returned is 'online' or 'offline'
my ($status) = $sth->fetchrow_array;

print $cgi->header( -charset => 'utf-8' );

my $tmpl = '';
while (<DATA>) {
    $_ =~ s/\[%\s+status\s+%\]/$status/gi;
    $tmpl .= $_;
}
print $tmpl;

__DATA__
<!DOCTYPE html>
<html>
<head>
<script src="http://code.jquery.com/jquery.min.js"></script>
<link href="http://getbootstrap.com/dist/css/bootstrap.css" rel="stylesheet" type="text/css" />
<script src="http://getbootstrap.com/dist/js/bootstrap.js"></script>

<meta charset="utf-8">
<meta http-equiv="refresh" content="5"> 

<title>Painel</title>

<style>
.status {
  color: #fff;
  font-weight: bolder;
  width: 100px;
  height: 100px;
  border:solid 1px #eaeaea;
  border-radius:50px;
  vertical-align:middle;
  text-align:center;
  line-height:90px;
  margin-left:auto;
  margin-right:auto;
}

.status-online {
  background-color: green;
}

.status-offline {
  background-color: red;
}
</style>

</head>
<body>
<div class="container">
<div class="row">
<div class="col-md-4 col-md-offset-4 text-center">
<div class="status status-[% status %]">
  <span>[% status %]</span>
</div>
</div>
</div>
</div>
</body>
</html>

