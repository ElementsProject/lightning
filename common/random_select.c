#include "config.h"
#include <common/pseudorand.h>
#include <common/random_select.h>

bool random_select(double weight, double *tot_weight)
{
	*tot_weight += weight;
	if (weight == 0)
		return false;

	return pseudorand_double() <= weight / *tot_weight;
}
