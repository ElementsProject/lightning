#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <ccan/list/list.h>
#include "helper.h"

#define ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING \
  (42)

struct opaque {
  struct list_node list;
  size_t secret_offset;
  char   secret_drawer[42];
};

static bool not_randomized = true;

struct opaque *create_opaque_blob(void)
{
  struct opaque *blob = calloc(1, sizeof(struct opaque));

  if (not_randomized) {
    srandom((int)time(NULL));
    not_randomized = false;
  }

  blob->secret_offset = random() % (sizeof(blob->secret_drawer));
  blob->secret_drawer[blob->secret_offset] =
    ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING;

  return blob;
}

bool if_blobs_know_the_secret(struct opaque *blob)
{
  bool answer = true;
  int i;
  for (i = 0; i < sizeof(blob->secret_drawer) /
               sizeof(blob->secret_drawer[0]); i++)
          if (i != blob->secret_offset)
                  answer = answer && (blob->secret_drawer[i] == 0);
          else
                  answer = answer &&
                          (blob->secret_drawer[blob->secret_offset] ==
           ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING);

  return answer;
}

void destroy_opaque_blob(struct opaque *blob)
{
  free(blob);
}


