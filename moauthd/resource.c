/*
 * Resource handling for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include "mmd.h"
#include <unistd.h>
#include <sys/fcntl.h>


/*
 * Local functions...
 */

static int		compare_resources(moauthd_resource_t *a, moauthd_resource_t *b);
static void		free_resource(moauthd_resource_t *resource);
static const char	*make_anchor(const char *text, char *buffer, size_t bufsize);
static void		write_block(moauthd_client_t *client, mmd_t *parent);
static void		write_leaf(moauthd_client_t *client, mmd_t *node);
static void		write_string(moauthd_client_t *client, const char *s);


/*
 * 'moauthdCreateResource()' - Create a resource record for a server.
 */

moauthd_resource_t *			/* O - New resource object */
moauthdCreateResource(
    moauthd_server_t  *server,		/* I - Server object */
    moauthd_restype_t type,		/* I - Resource type */
    const char        *remote_path,	/* I - Remote path */
    const char        *local_path,	/* I - Local path, if any */
    const char        *scope)		/* I - Scope string */
{
  moauthd_resource_t	*resource;	/* Resource object */


  resource = (moauthd_resource_t *)calloc(1, sizeof(moauthd_resource_t));

  resource->type = type;
  resource->remote_path = strdup(remote_path);
  resource->remote_len  = strlen(remote_path);
  resource->local_path  = local_path ? strdup(local_path) : NULL;
  resource->scope       = strdup(scope);

  pthread_rwlock_wrlock(&server->resources_lock);

  if (!server->resources)
    server->resources = cupsArrayNew3((cups_array_func_t)compare_resources, NULL, NULL, 0, NULL, (cups_afree_func_t)free_resource);

  cupsArrayAdd(server->resources, resource);

  pthread_rwlock_unlock(&server->resources_lock);

  return (resource);
}


/*
 * 'moauthdFindResource()' - Find the best matching resource for the request
 *                           path.
 */

moauthd_resource_t *			/* O - Matching resource */
moauthdFindResource(
    moauthd_server_t *server,		/* I - Server object */
    const char       *path_info,	/* I - Remote path */
    char             *name,		/* I - Filename buffer */
    size_t           namesize,		/* I - Size of filename buffer */
    struct stat      *info)		/* O - File information */
{
  int			i,		/* Looping var */
			count;		/* Number of resources */
  moauthd_resource_t	*resource,	/* Current resource */
			*best = NULL;	/* Best match */


 /*
  * Find the best matching (longest path match) resource based on the remote
  * path...
  */

  pthread_rwlock_rdlock(&server->resources_lock);

  for (i = 0, count = cupsArrayCount(server->resources); i < count; i ++)
  {
    resource = cupsArrayIndex(server->resources, i);

    if (!strncmp(path_info, resource->remote_path, resource->remote_len) && (!path_info[resource->remote_len] || path_info[resource->remote_len] == '/'))
    {
      if (!best || resource->remote_len > best->remote_len)
        best = resource;
    }
  }

  pthread_rwlock_unlock(&server->resources_lock);

  if (best && best->local_path)
  {
   /*
    * Map local filename...
    */

    if (path_info[best->remote_len])
    {
     /*
      * Directory match...
      */

      snprintf(name, namesize, "%s%s", best->local_path, path_info + best->remote_len);
    }
    else
    {
     /*
      * Exact match...
      */

      strncpy(name, best->local_path, namesize - 1);
      name[namesize - 1] = '\0';
    }

   /*
    * Make sure we can access the file or directory...
    */

    if (stat(name, info) || (S_ISDIR(info->st_mode) && best->type == MOAUTHD_RESTYPE_FILE) || (!S_ISDIR(info->st_mode) && !S_ISREG(info->st_mode)))
    {
     /*
      * No, return NULL for no match...
      */

      best  = NULL;
      *name = '\0';
    }
    else if (S_ISDIR(info->st_mode))
    {
     /*
      * Directory match, see if we have an index file...
      */

      char	temp[1024];		/* Temporary filename buffer */

      snprintf(temp, sizeof(temp), "%s/index.md", name);
      if (stat(temp, info))
        snprintf(temp, sizeof(temp), "%s/index.html", name);

      if (stat(temp, info))
      {
        best  = NULL;
        *name = '\0';
      }
      else
      {
        strncpy(name, temp, namesize - 1);
        name[namesize - 1] = '\0';
      }
    }
  }
  else if (best && best->type == MOAUTHD_RESTYPE_STATIC_FILE)
  {
    info->st_mode  = S_IFREG | 0444;
    info->st_uid   = getuid();
    info->st_gid   = getgid();
    info->st_mtime = server->start_time;
    info->st_size  = best->length;
  }

  return (best);
}


/*
 * 'moauthdGetFile()' - Get the named resource file.
 *
 * This function is also responsible for authorizing client access to the named
 * resource.
 */

int					/* O - HTTP status */
moauthdGetFile(moauthd_client_t *client)/* I - Client object */
{
  moauthd_resource_t	*best;		/* Matching resource */
  char			localfile[1024];/* Local filename */
  struct stat		localinfo;	/* Local file information */
  const char		*ext,		/* Extension on local file */
			*content_type;	/* Content type of file */


 /*
  * Find the file...
  */

  if ((best = moauthdFindResource(client->server, client->path_info, localfile, sizeof(localfile), &localinfo)) == NULL)
  {
    moauthdRespondClient(client, HTTP_STATUS_NOT_FOUND, NULL, 0, 0);
    return (HTTP_STATUS_NOT_FOUND);
  }

 /*
  * Serve the file...
  */

  if ((ext = strrchr(client->path_info, '.')) == NULL)
    ext = ".txt";

  if (!strcmp(ext, ".css"))
    content_type = "text/css";
  else if (!strcmp(ext, ".html") || !strcmp(ext, ".md"))
    content_type = "text/html";
  else if (!strcmp(ext, ".jpg"))
    content_type = "image/jpg";
  else if (!strcmp(ext, ".js"))
    content_type = "text/javascript";
  else if (!strcmp(ext, ".pdf"))
    content_type = "application/pdf";
  else if (!strcmp(ext, ".png"))
    content_type = "image/png";
  else
    content_type = "text/plain";

  if (client->request_method == HTTP_STATE_GET)
  {
    if (best->data)
    {
     /*
      * Serve a static/cached file...
      */

      moauthdRespondClient(client, HTTP_STATUS_OK, content_type, localinfo.st_mtime, best->length);

      if (httpWrite2(client->http, best->data, best->length) < best->length)
        return (HTTP_STATUS_BAD_REQUEST);
    }
    else if (!strcmp(ext, ".md"))
    {
     /*
      * Serve a Markdown file...
      */

      mmd_t	*doc = mmdLoad(localfile);
					/* Markdown document */
      const char *title = mmdGetMetadata(doc, "title");
					/* Document title */

      moauthdRespondClient(client, HTTP_STATUS_OK, content_type, localinfo.st_mtime, 0);
      moauthdHTMLHeader(client, title);
      write_block(client, doc);
      moauthdHTMLFooter(client);
    }
    else
    {
     /*
      * Server any other file...
      */

      int	fd;			/* File descriptor */
      char	buffer[16384];		/* Buffer */
      ssize_t	bytes;			/* Bytes read/written */

      if ((fd = open(localfile, O_RDONLY)) >= 0)
      {
	moauthdRespondClient(client, HTTP_STATUS_OK, content_type, localinfo.st_mtime, localinfo.st_size);

        while ((bytes = read(fd, buffer, sizeof(buffer))) > 0)
          httpWrite2(client->http, buffer, (size_t)bytes);

        close(fd);
      }
      else
      {
	moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, 0, 0);
	return (HTTP_STATUS_BAD_REQUEST);
      }
    }
  }

  return (HTTP_STATUS_OK);
}


/*
 * 'compare_resources()' - Compare the remote path of two resource objects...
 */

static int				/* O - Result of comparison */
compare_resources(moauthd_resource_t *a,/* I - First resource */
                  moauthd_resource_t *b)/* I - Second resource */
{
  return (strcmp(a->remote_path, b->remote_path));
}


/*
 * 'free_resource()' - Free a resource object.
 */

static void
free_resource(
    moauthd_resource_t *resource)	/* I - Resource object */
{
  free(resource->remote_path);
  if (resource->local_path)
    free(resource->local_path);
  free(resource->scope);
  free(resource);
}


/*
 * 'make_anchor()' - Make an anchor for internal links.
 */

static const char *                     /* O - Anchor string */
make_anchor(const char *text,           /* I - Text */
            char       *buffer,		/* I - Buffer */
            size_t     bufsize)		/* I - Size of buffer */
{
  char	*bufptr,			/* Pointer into buffer */
	*bufend = buffer + bufsize - 1;	/* End of buffer */


  for (bufptr = buffer; *text && bufptr < bufend; text ++)
  {
    if ((*text >= '0' && *text <= '9') || (*text >= 'a' && *text <= 'z') || (*text >= 'A' && *text <= 'Z') || *text == '.' || *text == '-')
      *bufptr++ = (char)tolower(*text & 255);
    else if (*text == ' ')
      *bufptr++ = '-';
  }

  *bufptr = '\0';

  return (buffer);
}


/*
 * 'write_block()' - Write a block node as HTML.
 */

static void
write_block(moauthd_client_t *client,	/* I - Client connection */
            mmd_t            *parent)	/* I - Parent node */
{
  const char    *element;               /* Enclosing element, if any */
  mmd_t         *node;                  /* Current child node */
  mmd_type_t    type;                   /* Node type */


  switch (type = mmdGetType(parent))
  {
    case MMD_TYPE_BLOCK_QUOTE :
        element = "blockquote";
        break;

    case MMD_TYPE_ORDERED_LIST :
        element = "ol";
        break;

    case MMD_TYPE_UNORDERED_LIST :
        element = "ul";
        break;

    case MMD_TYPE_LIST_ITEM :
        element = "li";
        break;

    case MMD_TYPE_HEADING_1 :
        element = "h1";
        break;

    case MMD_TYPE_HEADING_2 :
        element = "h2";
        break;

    case MMD_TYPE_HEADING_3 :
        element = "h3";
        break;

    case MMD_TYPE_HEADING_4 :
        element = "h4";
        break;

    case MMD_TYPE_HEADING_5 :
        element = "h5";
        break;

    case MMD_TYPE_HEADING_6 :
        element = "h6";
        break;

    case MMD_TYPE_PARAGRAPH :
        element = "p";
        break;

    case MMD_TYPE_CODE_BLOCK :
        write_string(client, "    <pre><code>");
        for (node = mmdGetFirstChild(parent); node; node = mmdGetNextSibling(node))
          moauthdHTMLPrintf(client, "%s", mmdGetText(node));
        write_string(client, "</code></pre>\n");
        return;

    case MMD_TYPE_THEMATIC_BREAK :
        write_string(client, "    <hr />\n");
        return;

    default :
        element = NULL;
        break;
  }

  if (type >= MMD_TYPE_HEADING_1 && type <= MMD_TYPE_HEADING_6)
  {
   /*
    * Add an anchor for each heading...
    */

    moauthdHTMLPrintf(client, "    <%s><a id=\"", element);
    for (node = mmdGetFirstChild(parent); node; node = mmdGetNextSibling(node))
    {
      char	anchor[1024];		/* Anchor string */

      if (mmdGetWhitespace(node))
        write_string(client, "-");
      write_string(client, make_anchor(mmdGetText(node), anchor, sizeof(anchor)));
    }
    write_string(client, "\">");
  }
  else if (element)
    moauthdHTMLPrintf(client, "    <%s>%s", element, type <= MMD_TYPE_UNORDERED_LIST ? "\n" : "");

  for (node = mmdGetFirstChild(parent); node; node = mmdGetNextSibling(node))
  {
    if (mmdIsBlock(node))
      write_block(client, node);
    else
      write_leaf(client, node);
  }

  if (type >= MMD_TYPE_HEADING_1 && type <= MMD_TYPE_HEADING_6)
    moauthdHTMLPrintf(client, "</a></%s>\n", element);
  else if (element)
    moauthdHTMLPrintf(client, "</%s>\n", element);
}


/*
 * 'write_leaf()' - Write a leaf node as HTML.
 */

static void
write_leaf(moauthd_client_t *client,	/* I - Client connection */
           mmd_t            *node)	/* I - Leaf node */
{
  const char    *element,               /* Encoding element, if any */
                *text,                  /* Text to write */
                *url;                   /* URL to write */


  if (mmdGetWhitespace(node))
    write_string(client, " ");

  text = mmdGetText(node);
  url  = mmdGetURL(node);

  switch (mmdGetType(node))
  {
    case MMD_TYPE_EMPHASIZED_TEXT :
        element = "em";
        break;

    case MMD_TYPE_STRONG_TEXT :
        element = "strong";
        break;

    case MMD_TYPE_STRUCK_TEXT :
        element = "del";
        break;

    case MMD_TYPE_LINKED_TEXT :
        element = NULL;
        break;

    case MMD_TYPE_CODE_TEXT :
        element = "code";
        break;

    case MMD_TYPE_IMAGE :
        moauthdHTMLPrintf(client, "<img src=\"%s\" alt=\"%s\" />", url, text);
        return;

    case MMD_TYPE_HARD_BREAK :
        write_string(client, "<br />\n");
        return;

    case MMD_TYPE_SOFT_BREAK :
        write_string(client, "<wbr />\n");
        return;

    case MMD_TYPE_METADATA_TEXT :
        return;

    default :
        element = NULL;
        break;
  }

  if (url)
  {
    char	anchor[1024];		/* Anchor string */

    if (!strcmp(url, "@"))
      moauthdHTMLPrintf(client, "<a href=\"#%s\">", make_anchor(text, anchor, sizeof(anchor)));
    else
      moauthdHTMLPrintf(client, "<a href=\"%s\">", url);
  }

  if (element)
    moauthdHTMLPrintf(client, "<%s>", element);

  if (!strcmp(text, "(c)"))
    write_string(client, "&copy;");
  else if (!strcmp(text, "(r)"))
    write_string(client, "&reg;");
  else if (!strcmp(text, "(tm)"))
    write_string(client, "&trade;");
  else
    moauthdHTMLPrintf(client, "%s", text);

  if (element)
    moauthdHTMLPrintf(client, "</%s>", element);

  if (url)
    write_string(client, "</a>");
}


/*
 * 'write_string()' - Write a string to the client...
 */

static void
write_string(moauthd_client_t *client,	/* I - Client connection */
             const char       *s)	/* I - String to write */
{
  httpWrite2(client->http, s, strlen(s));
}
