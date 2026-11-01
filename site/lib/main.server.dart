/// Static Jaspr documentation site for pqforge.
library;

import 'package:jaspr/dom.dart';
import 'package:jaspr/server.dart';
import 'package:jaspr_content/components/callout.dart';
import 'package:jaspr_content/components/sidebar.dart';
import 'package:jaspr_content/jaspr_content.dart';
import 'package:jaspr_content/theme.dart';

import 'components/site_header.dart';
import 'main.server.options.dart';

void main() {
  Jaspr.initializeApp(options: defaultServerOptions);

  runApp(
    ContentApp(
      eagerlyLoadAllPages: true,
      templateEngine: MustacheTemplateEngine(),
      parsers: [MarkdownParser()],
      extensions: [HeadingAnchorsExtension(), TableOfContentsExtension()],
      components: [Callout()],
      layouts: [
        DocsLayout(
          header: const SiteHeader(),
          sidebar: const Sidebar(
            groups: [
              SidebarGroup(
                links: [SidebarLink(text: 'Overview', href: './')],
              ),
              SidebarGroup(
                title: 'Use it',
                links: [
                  SidebarLink(text: 'Getting started', href: 'getting-started'),
                  SidebarLink(text: 'HPKE', href: 'hpke'),
                  SidebarLink(text: 'Certificates', href: 'certificates'),
                  SidebarLink(text: 'Symmetric', href: 'symmetric'),
                  SidebarLink(text: 'Classical', href: 'classical'),
                ],
              ),
              SidebarGroup(
                title: 'Boundary',
                links: [
                  SidebarLink(text: 'Claim boundary', href: 'claim-boundary'),
                ],
              ),
            ],
          ),
          footer: footer(classes: 'site-footer', [
            p([
              Component.text(
                'pqforge 0.4.10. Built with Dart and Jaspr. '
                'Not a FIPS 140 module. ',
              ),
              a(
                href: 'https://github.com/turkananation/pqforge',
                target: Target.blank,
                [Component.text('GitHub')],
              ),
              Component.text(' · '),
              a(
                href: 'https://pub.dev/packages/pqforge',
                target: Target.blank,
                [Component.text('pub.dev')],
              ),
              Component.text(' · '),
              a(
                href: 'https://turkananation.github.io/pqcrypto',
                target: Target.blank,
                [Component.text('pqcrypto')],
              ),
              Component.text(' · '),
              a(
                href: 'https://turkananation.github.io/pqtransport',
                target: Target.blank,
                [Component.text('pqtransport')],
              ),
            ]),
          ]),
        ),
      ],
      theme: ContentTheme(
        primary: ThemeColor(Color('#3f6212'), dark: Color('#d6f25c')),
        background: ThemeColor(Color('#f4f7f2'), dark: Color('#0c1110')),
        text: ThemeColor(Color('#14211a'), dark: Color('#e7f2ea')),
        colors: [
          ContentColors.links.apply(
            ThemeColor(Color('#3f6212'), dark: Color('#d6f25c')),
          ),
          ContentColors.quoteBorders.apply(
            ThemeColor(Color('#9a3412'), dark: Color('#fb923c')),
          ),
          ContentColors.preBg.apply(
            ThemeColor(Color('#14211a'), dark: Color('#070b0a')),
          ),
        ],
      ),
    ),
  );
}
