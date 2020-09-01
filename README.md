# tiklist

tiklist generates RouterOS scripts to import common blocklists.

To use this, you'd run this on the local network, then add a script
to the router which fetches the lists it needs. For example, for a
server running at `10.0.0.10:42563`, make a script called `updateLists`:

```
:local log do={ :put $t; :log warning $t }

:local lists {
    "spamhaus_drop";
    "spamhaus_edrop";
    "dshield";
    "okean";
    "myip";
    "emerging_threats";
}

:local rscPath "disk3/tmp.rsc"

:foreach list in=$lists do={
    :local url ("http://10.0.0.10/$list" . ".rsc");

    $log t=("Fetching " . "$url");
    /tool fetch mode=http port=42563 dst-path=$rscPath url=$url;

    :delay 1;

    :local dlsz [:tonum [/file get [ find where name=$rscPath] value-name=size]];

    :if ($dlsz < 100) do={
        :put "Download failed. Received $dlsz bytes.";
        :log error "Download failed. Received $dlsz bytes.";
    }

    /import file-name="$rscPath";

    :do { /file remove [find name=$rscPath]; } on-error={ $log t="Error deleting temp file." };
}
```

Then schedule this to run once a day:

```
/system script run updateLists
```

And on startup:

```
:delay 15;
/system script run updateLists
```
