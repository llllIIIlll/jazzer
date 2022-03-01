// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.sanitizers.utils;

import java.lang.reflect.Field;

public final class ReflectionUtils {
  public static final class ReflectionError extends Error {
    public ReflectionError(Throwable cause) {
      super(cause);
    }
  }

  public static Class<?> clazz(String className) {
    try {
      return Class.forName(className);
    } catch (ClassNotFoundException e) {
      throw new ReflectionError(e);
    }
  }

  public static Class<?> nestedClass(Class<?> parentClass, String nestedClassName) {
    return clazz(parentClass.getName() + "$" + nestedClassName);
  }

  public static Field field(Class<?> clazz, String fieldName) {
    try {
      return clazz.getDeclaredField(fieldName);
    } catch (NoSuchFieldException e) {
      throw new ReflectionError(e);
    }
  }
}
