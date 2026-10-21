package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Shader
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import kotlin.math.min
import kotlin.math.roundToInt

/** Presentation only: indices and selection callbacks retain the existing protocol contract. */
class TransportRail(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val labels: List<String>,
    private val onPick: (Int) -> Unit,
) : FrameLayout(context) {
    val rowCount = 2
    private val density = resources.displayMetrics.density
    private fun dp(v: Float) = v * density
    private val cards = mutableListOf<MethodCard>()
    private var selectedIndex = 0
    private var connecting = false
    private val icons = listOf(
        R.drawable.method_wireguard, R.drawable.method_masque, 0,
        R.drawable.method_psiphon, R.drawable.method_tor,
        R.drawable.method_foxy, R.drawable.method_shard,
    )
    private val names = listOf("WireGuard", "MASQUE", "WoW", "Psiphon", "Tor", "Foxy", "SHARD")

    init {
        layoutDirection = View.LAYOUT_DIRECTION_LTR
        background = android.graphics.drawable.GradientDrawable().apply {
            setColor(Color.rgb(10, 19, 24))
            cornerRadius = dp(18f)
            setStroke(dp(1f).roundToInt(), Color.rgb(48, 81, 86))
        }
        labels.indices.forEach { index ->
            val card = MethodCard(context, names.getOrElse(index) { labels[index] }, icons.getOrElse(index) { 0 }).apply {
                contentDescription = labels[index]
                isFocusable = true
                isClickable = true
                setOnClickListener {
                    if (!this@TransportRail.isEnabled) return@setOnClickListener
                    performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                    select(index, true)
                    onPick(index)
                }
            }
            cards.add(card)
            addView(card)
        }
        select(0, false)
    }

    // Both rows share one center. The top row is 90% of the bottom row's width.
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val w = MeasureSpec.getSize(widthMeasureSpec)
        val h = MeasureSpec.getSize(heightMeasureSpec)
        setMeasuredDimension(w, h)
        val gap = dp(3f)
        val bottomWidth = w - dp(12f)
        val topWidth = bottomWidth * .90f
        val ch = ((h - dp(14f)) / 2f).roundToInt().coerceAtLeast(1)
        cards.forEachIndexed { i, card ->
            val count = if (i < 3) 3 else 4
            val rowWidth = if (i < 3) topWidth else bottomWidth
            val cw = ((rowWidth - gap * (count - 1)) / count).roundToInt().coerceAtLeast(1)
            card.measure(MeasureSpec.makeMeasureSpec(cw, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(ch, MeasureSpec.EXACTLY))
        }
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val gap = dp(3f)
        for (row in 0..1) {
            val start = if (row == 0) 0 else 3
            val end = min(if (row == 0) 3 else 7, cards.size)
            if (start >= end) continue
            val rowWidth = (start until end).sumOf { cards[it].measuredWidth } + gap * (end - start - 1)
            var x = (width - rowWidth) / 2f
            val y = dp(5f) + row * (cards[start].measuredHeight + dp(4f))
            for (i in start until end) {
                val c = cards[i]
                c.layout(x.roundToInt(), y.roundToInt(), (x + c.measuredWidth).roundToInt(), (y + c.measuredHeight).roundToInt())
                x += c.measuredWidth + gap
            }
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun select(index: Int, animate: Boolean) {
        if (index !in cards.indices) return
        selectedIndex = index
        refreshCards()
    }

    fun setConnecting(value: Boolean) {
        if (connecting == value) return
        connecting = value
        refreshCards()
    }

    private fun refreshCards() {
        cards.forEachIndexed { i, c ->
            c.isSelected = i == selectedIndex
            c.accent = when {
                i != selectedIndex -> Color.rgb(58, 73, 82)
                connecting -> Color.rgb(255, 153, 61)
                else -> Color.rgb(50, 238, 194)
            }
            c.invalidate()
        }
    }

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        // Preserve selected/connecting visibility while preventing mode changes.
        cards.forEach { it.isEnabled = enabled }
    }

    private inner class MethodCard(context: Context, name: String, icon: Int) : FrameLayout(context) {
        var accent = Color.rgb(58, 73, 82)
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val bounds = RectF()
        private val logo: View = if (icon != 0) ImageView(context).apply {
            setImageResource(icon)
            scaleType = ImageView.ScaleType.FIT_CENTER
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        } else TextView(context).apply {
            text = "W"
            gravity = Gravity.CENTER
            textSize = 20f
            typeface = android.graphics.Typeface.create("serif", android.graphics.Typeface.BOLD)
            setTextColor(Color.rgb(255, 210, 106))
            background = android.graphics.drawable.GradientDrawable(
                android.graphics.drawable.GradientDrawable.Orientation.TL_BR,
                intArrayOf(Color.rgb(111, 78, 23), Color.rgb(30, 23, 10)),
            ).apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setStroke(dp(1f).roundToInt(), Color.rgb(189, 146, 58))
            }
        }
        private val title = TextView(context).apply {
            text = name
            gravity = Gravity.CENTER_VERTICAL
            setTextColor(Color.rgb(235, 241, 244))
            typeface = Typefaces.medium(context)
            setSingleLine(true)
            letterSpacing = 0f
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }

        init {
            setWillNotDraw(false)
            addView(logo)
            addView(title)
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            val w = MeasureSpec.getSize(widthMeasureSpec)
            val h = MeasureSpec.getSize(heightMeasureSpec)
            setMeasuredDimension(w, h)
            val size = min(dp(23f), h - dp(12f)).roundToInt().coerceAtLeast(1)
            logo.measure(MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY))
            val available = (w - size - dp(12f)).roundToInt().coerceAtLeast(1)
            title.textSize = 11f
            val desired = title.paint.measureText(title.text.toString())
            if (desired > available) title.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, title.textSize * available / desired)
            title.measure(MeasureSpec.makeMeasureSpec(available, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(h, MeasureSpec.EXACTLY))
        }

        override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
            val x = dp(5f).roundToInt()
            val y = (height - logo.measuredHeight) / 2
            logo.layout(x, y, x + logo.measuredWidth, y + logo.measuredHeight)
            val tx = x + logo.measuredWidth + dp(3f).roundToInt()
            title.layout(tx, 0, tx + title.measuredWidth, height)
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            bounds.set(dp(2f), dp(2f), width - dp(2f), height - dp(2f))
            val radius = dp(11f)
            paint.style = Paint.Style.FILL
            paint.shader = LinearGradient(0f, 0f, 0f, height.toFloat(), Color.rgb(37, 49, 57), Color.rgb(17, 27, 33), Shader.TileMode.CLAMP)
            canvas.drawRoundRect(bounds, radius, radius, paint)
            paint.shader = null
            paint.style = Paint.Style.STROKE
            if (isSelected) {
                // Static layered glow: no timer, animation loop or software layer.
                paint.color = Color.argb(32, Color.red(accent), Color.green(accent), Color.blue(accent))
                paint.strokeWidth = dp(5f)
                canvas.drawRoundRect(bounds, radius, radius, paint)
            }
            paint.color = accent
            paint.strokeWidth = dp(if (isSelected) 2f else 1f)
            canvas.drawRoundRect(bounds, radius, radius, paint)
        }
    }
}
