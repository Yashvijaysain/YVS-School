import {
  clerkMiddleware,
  createRouteMatcher,
  clerkClient,
} from "@clerk/nextjs/server";
import { NextResponse } from "next/server";

const publicRoutes = ["/", "/sign-in"];

export default clerkMiddleware(async (auth, req) => {
  const { userId, sessionClaims } = auth();
  const { pathname } = req.nextUrl;

  // Public route access
  if (!userId && publicRoutes.includes(pathname)) {
    return NextResponse.next();
  }

  // Unauthenticated users trying to access protected routes
  if (!userId && !publicRoutes.includes(pathname)) {
    return NextResponse.redirect(new URL("/sign-in", req.url));
  }

  if (userId) {
    try {
      const user = await clerkClient.users.getUser(userId);
      const role = user.publicMetadata?.role as string | undefined;

      if (!role) {
        return NextResponse.redirect(new URL("/unauthorized", req.url));
      }

      // Redirect user to their role dashboard after sign-in
      if (
        pathname === "/sign-in" ||
        pathname === "/sign-up" ||
        pathname === "/"
      ) {
        return NextResponse.redirect(new URL(`/${role}`, req.url));
      }

      // Prevent non-admins from accessing /admin
      if (pathname.startsWith("/admin") && role !== "admin") {
        return NextResponse.redirect(new URL(`/${role}`, req.url));
      }
    } catch (error) {
      console.error("Error fetching user from Clerk:", error);
      return NextResponse.redirect(new URL("/error", req.url));
    }
  }

  return NextResponse.next();
});

export const config = {
  matcher: [
    // Allow for all app routes except static files and _next
    "/((?!_next|[^?]*\\.(?:html?|css|js|json|jpg|png|svg|ico|woff2?)$).*)",
    "/(api|trpc)(.*)",
  ],
};
