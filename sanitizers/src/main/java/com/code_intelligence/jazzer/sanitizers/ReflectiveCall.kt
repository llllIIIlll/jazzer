// Copyright 2021 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle

/**
 * Detects unsafe reflective calls that lead to attacker-controlled method calls.
 */
@Suppress("unused_parameter", "unused")
object ReflectiveCall {

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Class", targetMethod = "forName")
    @JvmStatic
    fun classForNameHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val className = args[0] as? String ?: return
        Jazzer.guideTowardsEquality(className, HONEYPOT_CLASS_NAME, hookId)
    }

    @MethodHooks(
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Runtime", targetMethod = "load"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Runtime", targetMethod = "loadLibrary"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "load"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "loadLibrary"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "mapLibraryName"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.ClassLoader", targetMethod = "findLibrary"),
    )
    @JvmStatic
    fun loadLibraryHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val libraryName = args[0] as? String ?: return
        if (libraryName == HONEYPOT_LIBRARY_NAME) {
            Jazzer.reportFindingFromHook(
                FuzzerSecurityIssueHigh("load arbitrary library")
            )
        }
        Jazzer.guideTowardsEquality(libraryName, HONEYPOT_LIBRARY_NAME, hookId)
    }
}
