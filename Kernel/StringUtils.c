#include "StringUtils.h"

#include <linux/slab.h>

int string_compare_with_wildcards(const char *wild, const char *string) 
{
  const char *cp = NULL, *mp = NULL;

  while ((*string) && (*wild != '*')) 
  {
    if ((*wild != *string) && (*wild != '?')) 
    {
      return 0;
    }
    wild++;
    string++;
  }

  while (*string) {
    if (*wild == '*') 
    {
      if (!*++wild) 
      {
        return 1;
      }
      mp = wild;
      cp = string+1;
    } 
    else if ((*wild == *string) || (*wild == '?')) 
    {
      wild++;
      string++;
    } else 
    {
      wild = mp;
      string = cp++;
    }
  }

  while (*wild == '*') 
  {
    wild++;
  }
  return !*wild;
}

int join_strings_from_user(const char __user *const __user *ups, const char *delim, char *buff, size_t bufcap)
{
    int index = 0;
    const char __user* up;
    char *tmp = kmalloc(bufcap, GFP_KERNEL);
    if (unlikely(!tmp))
    {
        return index;
    }

    while(copy_from_user(&up, ups + index, sizeof(up)) == 0)
    {
        memset(tmp, 0, bufcap);
        if (strncpy_from_user(tmp, up, strnlen_user(up, bufcap)) <= 0)
        {
            goto join_strings_from_user_exit;
        }
        if(index > 0)
        {
            strlcat(buff, delim, bufcap);
        }

        strlcat(buff, tmp, bufcap);
        ++index;
    }


join_strings_from_user_exit:
    kfree(tmp);
    return index;
}