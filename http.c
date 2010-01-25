
  if(-1 == (listenfd = socket(pf_inet, sock_stream, 0)))
  {
    perror("socket");

    return exit_failure;
  }

  int one = 1;
  setsockopt(listenfd, sol_socket, so_reuseaddr, &one, sizeof(one));

  struct sockaddr_in address;

  address.sin_family = af_inet;
  address.sin_addr.s_addr = htonl(inaddr_loopback);
  address.sin_port = htons(rpc_port);

  if(-1 == bind(listenfd, (struct sockaddr*) &address, sizeof(address)))
  {
    fprintf(stderr, "failed to bind to rpc port %d: %s\n", rpc_port, strerror(errno));

    return exit_failure;
  }

  if(-1 == listen(listenfd, 16))
  {
    fprintf(stderr, "failed to start listening on rpc port %d: %s\n", rpc_port, strerror(errno));

    return exit_failure;
  }
    clientfd = accept(listenfd, (struct sockaddr*) &addr, &addrlen);

  struct rpc_arg* arg = (struct rpc_arg*) varg;

  const size_t buf_size = 4096;
  char* buf = new char[buf_size + 1];
  size_t buf_fill = 0;

  try
  {
    for(;;)
    {
      int res;

      if(buf_fill == buf_size)
        break;

      res = read(arg->fd, buf, buf_size - buf_fill);

      if(res <= 0)
        break;

      buf_fill += res;
      buf[buf_fill] = 0;

      char* end;

      if(0 != (end = strstr(buf, "\r\n\r\n")))
        end += 3;
      else if(0 != (end = strstr(buf, "\n\n")))
        ++end;
      else
        continue;

      *end = 0;

      char* line_saveptr;
      char* line;

      line = strtok_r(buf, "\r\n", &line_saveptr);

      if(!line)
        break;

      char* method = 0;
      char* path = 0;
      char* protocol = 0;

      if(3 != sscanf(line, "%as %as %as", &method, &path, &protocol))
      {
        free(method);
        free(path);
        free(protocol);

        break;
      }

      if(strcmp(method, "POST"))
      {
        write_all(arg->fd, error501, strlen(error501));

        break;
      }

      ssize_t content_length = -1;
      int expect_100_continue = 0;

      while(0 != (line = strtok_r(0, "\r\n", &line_saveptr)))
      {
        char* key;
        char* value;

        key = line;
        value = strchr(key, ':');

        if(!value)
          break;

        *value++ = 0;

        while(*value == ' ')
          ++value;

        if(!strcasecmp(key, "content-length"))
        {
          content_length = strtol(value, 0, 10);
        }
        else if(!strcasecmp(key, "expect"))
        {
          if(!strcasecmp(value, "100-continue"))
            expect_100_continue = 1;
        }

        line = strtok_r(0, "\r\n", &line_saveptr);
      }

      buf_fill -= (end - buf + 1);
      memmove(buf, end + 1, buf_fill);

      if(content_length > 0)
      {
        char* payload = new char[content_length + 1];
        size_t remaining = content_length;

        if(expect_100_continue
           && -1 == write_all(arg->fd, continue100, strlen(continue100)))
          break;

        if(buf_fill)
        {
          if(buf_fill < (size_t) content_length)
          {
            memcpy(payload, buf, buf_fill);
            buf_fill = 0;
            remaining -= buf_fill;
          }
          else
          {
            memcpy(payload, buf, content_length);
            buf_fill -= content_length;
            remaining = 0;
          }
        }

        while(remaining)
        {
          res = read(arg->fd, payload + (content_length - remaining), remaining);

          if(res <= 0)
            goto disconnect;

          remaining -= res;
        }

        payload[content_length] = 0;

        //url_decode(payload);

        handle_json_request(arg, payload, content_length);

        delete [] payload;
      }
    }
  }
