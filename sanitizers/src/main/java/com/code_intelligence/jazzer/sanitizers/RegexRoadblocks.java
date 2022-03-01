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

package com.code_intelligence.jazzer.sanitizers;

import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.field;
import static com.code_intelligence.jazzer.sanitizers.utils.ReflectionUtils.nestedClass;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import com.code_intelligence.jazzer.runtime.UnsafeProvider;
import java.lang.invoke.MethodHandle;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sun.misc.Unsafe;

public final class RegexRoadblocks {
  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final long SLICE_NODE_BUFFER_OFFSET =
      UNSAFE.objectFieldOffset(field(nestedClass(Pattern.class, "SliceNode"), "buffer"));
  private static final long CHAR_PROPERTY_PREDICATE =
      UNSAFE.objectFieldOffset(field(nestedClass(Pattern.class, "CharProperty"), "predicate"));
  // Weakly map CharPredicate instances to characters that satisfy the predicate. Since
  // CharPredicate instances are usually lambdas, we collect their solutions by hooking the
  // functions constructing them rather than extracting the solutions via reflection.
  private static final ThreadLocal<WeakHashMap<Object, Character>> PREDICATE_SOLUTIONS =
      ThreadLocal.withInitial(WeakHashMap::new);

  // Do not act on instrumented regexes used by Jazzer internally, e.g. by ClassGraph.
  private static boolean HOOK_DISABLED = true;

  static {
    Jazzer.onFuzzTargetReady(() -> HOOK_DISABLED = UNSAFE == null);
  }

  @MethodHook(type = HookType.BEFORE, targetClassName = "java.util.regex.Pattern$Node",
      targetMethod = "match",
      targetMethodDescriptor = "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z",
      additionalClassesToHook =
          {
              "java.util.regex.Matcher",
              "java.util.regex.Pattern$BackRef",
              "java.util.regex.Pattern$Behind",
              "java.util.regex.Pattern$BehindS",
              "java.util.regex.Pattern$BmpCharProperty",
              "java.util.regex.Pattern$BmpCharPropertyGreedy",
              "java.util.regex.Pattern$BnM",
              "java.util.regex.Pattern$BnMS",
              "java.util.regex.Pattern$Bound",
              "java.util.regex.Pattern$Branch",
              "java.util.regex.Pattern$BranchConn",
              "java.util.regex.Pattern$CharProperty",
              "java.util.regex.Pattern$CharPropertyGreedy",
              "java.util.regex.Pattern$CIBackRef",
              "java.util.regex.Pattern$Caret",
              "java.util.regex.Pattern$Curly",
              "java.util.regex.Pattern$Conditional",
              "java.util.regex.Pattern$First",
              "java.util.regex.Pattern$GraphemeBound",
              "java.util.regex.Pattern$GroupCurly",
              "java.util.regex.Pattern$GroupHead",
              "java.util.regex.Pattern$GroupRef",
              "java.util.regex.Pattern$LastMatch",
              "java.util.regex.Pattern$LazyLoop",
              "java.util.regex.Pattern$LineEnding",
              "java.util.regex.Pattern$Loop",
              "java.util.regex.Pattern$Neg",
              "java.util.regex.Pattern$NFCCharProperty",
              "java.util.regex.Pattern$NotBehind",
              "java.util.regex.Pattern$NotBehindS",
              "java.util.regex.Pattern$Pos",
              "java.util.regex.Pattern$Ques",
              "java.util.regex.Pattern$Slice",
              "java.util.regex.Pattern$SliceI",
              "java.util.regex.Pattern$SliceIS",
              "java.util.regex.Pattern$SliceS",
              "java.util.regex.Pattern$SliceU",
              "java.util.regex.Pattern$Start",
              "java.util.regex.Pattern$StartS",
              "java.util.regex.Pattern$UnixCaret",
              "java.util.regex.Pattern$UnixDollar",
              "java.util.regex.Pattern$XGrapheme",
          })
  public static void
  nodeMatchHook(MethodHandle method, Object node, Object[] args, int hookId) {
    if (HOOK_DISABLED)
      return;
    if (node == null)
      return;
    Matcher matcher = (Matcher) args[0];
    if (matcher == null)
      return;
    int i = (int) args[1];
    CharSequence seq = (CharSequence) args[2];
    if (seq == null)
      return;

    String current;
    String target;
    switch (nodeType(node)) {
      case "BnM":
      case "BnMS":
      case "SliceNode":
      case "Slice":
      case "SliceI":
      case "SliceU":
        current = seq.subSequence(i, limitedLength(matcher.regionEnd())).toString();

        // All these subclasses of SliceNode store the literal in an int[], which we have to
        // truncate to a char[].
        int[] buffer = (int[]) UNSAFE.getObject(node, SLICE_NODE_BUFFER_OFFSET);
        char[] charBuffer = new char[limitedLength(buffer.length)];
        for (int j = 0; j < charBuffer.length; j++) {
          charBuffer[j] = (char) buffer[j];
        }
        target = new String(charBuffer);
        break;
      case "BmpCharProperty":
      case "CharProperty":
        Object charPredicate = UNSAFE.getObject(node, CHAR_PROPERTY_PREDICATE);
        if (charPredicate == null)
          return;
        Character solution = PREDICATE_SOLUTIONS.get().get(charPredicate);
        if (solution == null)
          return;
        current = seq.subSequence(i, Math.min(i + 1, seq.length())).toString();
        target = Character.toString(solution);
        break;
      default:
        return;
    }
    // hookId only takes one distinct value per Node subclass. In order to get different regex
    // matches to be tracked similar to different instances of string compares, we mix in the hash
    // of the underlying pattern. We expect patterns to be static almost always, so that this should
    // not fill up the value profile map too quickly.
    Jazzer.guideTowardsEquality(current, target, hookId ^ matcher.pattern().toString().hashCode());
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.regex.Pattern",
      targetMethod = "Single",
      targetMethodDescriptor = "(I)Ljava/util/regex/Pattern$BmpCharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.regex.Pattern",
      targetMethod = "SingleS",
      targetMethodDescriptor = "(I)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void
  singleHook(MethodHandle method, Object node, Object[] args, int hookId, Object predicate) {
    PREDICATE_SOLUTIONS.get().put(predicate, (char) (int) args[0]);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.regex.Pattern",
      targetMethod = "Range",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.regex.Pattern",
      targetMethod = "CIRange",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.regex.Pattern",
      targetMethod = "CIRangeU",
      targetMethodDescriptor = "(II)Ljava/util/regex/Pattern$CharPredicate;",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void
  rangeHook(MethodHandle method, Object node, Object[] args, int hookId, Object predicate) {
    PREDICATE_SOLUTIONS.get().put(predicate, (char) (int) args[0]);
  }

  // For java.util.regex.Pattern$Slice, this returns Slice.
  private static String nodeType(Object node) {
    return node.getClass().getSimpleName();
  }

  // Limits a length to the maximum length libFuzzer will read up to in a callback.
  private static int limitedLength(int length) {
    return Math.min(length, 64);
  }
}
