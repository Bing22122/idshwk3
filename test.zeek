global x: table[addr] of set[string];
event http_header(c:connection,is_orig:bool,name:string,value:string)
{
     if (c$http?$user_agent)
     { 
       local user_agent = to_lower(c$http$user_agent);
       if(c$id$orig_h in x)
       {
        if(!(user_agent in x[c$id$orig_h]))
         {add x[c$id$orig_h][user_agent];}
       }
       else
       {
         x[c$id$orig_h]=set(user_agent);
       }
       
     }
    
}
event zeek_done()
{
  for(a in x)
  { 
     if(|x[a]|>=3)
     {
       print fmt("%s is a proxyaddr",a);
     }
  }
 }