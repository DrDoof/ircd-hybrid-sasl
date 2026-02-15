/^  const char \*id;$/ {
  print "  /* Guard: skip UID assignment if already set by m_sasl */"
  print "  if (client->id[0] == '\\0')"
  print "  {"
  print "    const char *id;"
  next
}
/^  while \(hash_find_id\(\(id = uid_get\(\)\)\)\)$/ {
  print "    while (hash_find_id((id = uid_get())))"
  next
}
/^    ;$/ && !done_semi {
  print "      ;"
  done_semi = 1
  next
}
/^  strlcpy\(client->id, id, sizeof\(client->id\)\);$/ {
  print "    strlcpy(client->id, id, sizeof(client->id));"
  next
}
/^  hash_add_id\(client\);$/ {
  print "    hash_add_id(client);"
  print "  }"
  next
}
{ print }
