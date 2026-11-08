import 'package:jaspr/dom.dart';
import 'package:jaspr/jaspr.dart';
import 'package:jaspr_content/components/github_button.dart';
import 'package:jaspr_content/components/sidebar_toggle_button.dart';
import 'package:jaspr_content/components/theme_toggle.dart';

/// Branded header for the pqforge documentation site.
class SiteHeader extends StatelessComponent {
  /// Creates the site header.
  const SiteHeader({super.key});

  @override
  Component build(BuildContext context) {
    return Component.fragment([
      Document.head(children: [Style(styles: _styles)]),
      header(classes: 'pqf-header', [
        const SidebarToggleButton(),
        a(classes: 'pqf-title', href: './', [
          span([Component.text('pqforge')]),
        ]),
        nav(classes: 'pqf-nav', [
          a(href: 'https://yardenah.com', [Component.text('Yardenah')]),
          a(href: 'hpke', [Component.text('HPKE')]),
          a(href: 'certificates', [Component.text('Certificates')]),
          a(href: 'symmetric', [Component.text('Symmetric')]),
          a(href: 'signatures', [Component.text('Signatures')]),
          a(href: 'claim-boundary', [Component.text('Boundary')]),
          const ThemeToggle(),
          const GitHubButton(repo: 'turkananation/pqforge'),
        ]),
      ]),
    ]);
  }

  static List<StyleRule> get _styles => [
    css('.pqf-header', [
      css('&').styles(
        height: 4.rem,
        display: Display.flex,
        alignItems: AlignItems.center,
        gap: Gap.column(.875.rem),
        padding: Padding.symmetric(horizontal: 1.rem, vertical: .25.rem),
        margin: Margin.symmetric(horizontal: Unit.auto),
        border: Border.only(
          bottom: BorderSide(color: Color('#d6f25c33'), width: 1.px),
        ),
      ),
      css(
        '.pqf-title',
      ).styles(fontWeight: FontWeight.w800, letterSpacing: Unit.zero),
      css('.pqf-nav', [
        css('&').styles(
          display: Display.flex,
          flex: Flex(grow: 1),
          alignItems: AlignItems.center,
          justifyContent: JustifyContent.end,
          gap: Gap.column(.75.rem),
        ),
        css('> a').styles(display: Display.none),
      ]),
    ]),
    css.media(MediaQuery.all(minWidth: 768.px), [
      css('.pqf-header .pqf-nav > a').styles(display: Display.inline),
    ]),
  ];
}
