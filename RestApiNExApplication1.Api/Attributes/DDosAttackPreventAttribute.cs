﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RestApiNExApplication1.Api.Attributes
{
    [AttributeUsage(AttributeTargets.Method)]
    public class DDosAttackProtectedAttribute : Attribute
    {
    }
}
