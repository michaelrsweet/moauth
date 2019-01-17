/*
 * moauth configuration header
 *
 * Copyright © 2017-2019 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

/* Version number... */
#define MOAUTH_VERSION "1.1"

/* Do we have the <sys/random.h> header? */
#define HAVE_SYS_RANDOM_H 1

/* Do we have the arc4random function? */
#define HAVE_ARC4RANDOM 1

/* PAM stuff... */
#define HAVE_LIBPAM 1
#define HAVE_SECURITY_PAM_APPL_H 1
/* #undef HAVE_PAM_PAM_APPL_H */
