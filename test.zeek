global StoU:table[addr] of set[string]= table();

event http_header(c: connection, is_orig: bool, name :string, value :string)
{
	if (name=="USER-AGENT")
	{
		if (c$id$orig_h in StoU) 
	  {
		  add StoU[c$id$orig_h][value];
	  }
	  else
	  {
		  StoU[c$id$orig_h]=set(value);
	  }
	}
}

event zeek_done()
{
	for (key in StoU)
	{
		if( |StoU[key]|>=3)
		print fmt("%s is a proxy",key);
	}
}
