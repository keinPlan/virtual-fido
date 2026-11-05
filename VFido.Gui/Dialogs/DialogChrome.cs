using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;

namespace VFido.Gui.Dialogs;

/// <summary>Shared rounded shell matching the security request window.</summary>
internal static class DialogChrome
{
    internal static void Apply(Window window)
    {
        var body = window.Content;
        window.Content = null;
        window.SystemDecorations = SystemDecorations.None;
        window.Background = Brushes.Transparent;
        window.TransparencyLevelHint = new[] { WindowTransparencyLevel.Transparent };

        var title = new TextBlock
        {
            FontSize = 15, FontWeight = FontWeight.SemiBold, Foreground = Brushes.White,
            VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
        };
        title.Bind(TextBlock.TextProperty, new Binding(nameof(Window.Title)) { Source = window });
        var close = new Button
        {
            Content = "×", Width = 32, Height = 30, Padding = new Thickness(0),
            Background = Brushes.Transparent, Foreground = Brushes.White,
            BorderThickness = new Thickness(0), FontSize = 20,
        };
        ToolTip.SetTip(close, "Close");
        close.Click += (_, _) => window.Close();
        var heading = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        heading.Children.Add(title);
        Grid.SetColumn(close, 1);
        heading.Children.Add(close);
        var header = new Border
        {
            Background = Brush.Parse("#232634"), Padding = new Thickness(16, 10), Child = heading,
        };
        header.PointerPressed += (_, e) =>
        {
            if (e.GetCurrentPoint(header).Properties.IsLeftButtonPressed &&
                (ReferenceEquals(e.Source, header) || ReferenceEquals(e.Source, heading) || ReferenceEquals(e.Source, title)))
                window.BeginMoveDrag(e);
        };
        var content = new ContentControl { Content = body };
        var layout = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        layout.Children.Add(header);
        Grid.SetRow(content, 1);
        layout.Children.Add(content);
        var shell = new Border
        {
            CornerRadius = new CornerRadius(12), BorderBrush = Brush.Parse("#232634"),
            BorderThickness = new Thickness(1), ClipToBounds = true, Child = layout,
        };
        shell.Bind(Border.BackgroundProperty, window.GetResourceObservable("VFidoSurfaceBrush"));
        window.Content = shell;
    }
}
